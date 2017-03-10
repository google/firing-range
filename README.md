# What is Firing Range?

Firing Range is a test bed for web application security scanners,
providing synthetic, wide coverage for an array of vulnerabilities.

It can be deployed as a Google App Engine application. A public instance
is running at https://public-firing-range.appspot.com.

# Local installation instructions

1. `sudo apt-get install git ant`
1. Download the Appengine SDK for Java from
   http://cloud.google.com/appengine/downloads and unzip it in a directory.
1. `mkdir github && cd github`
1. `git clone https://github.com/google/firing-range.git`
1. `cd firing-range`
1. Modify `build.xml` so that the `appengine.sdk` property points to the
   directory where you unpacked the appengine SDK (you could also unpack it
   on `../../`, which is the default)
1. `ant runserver`

The application then will be run locally at http://localhost:8080

# License information

See the LICENSE file.
