# libwatchman [![Build Status](https://secure.travis-ci.org/twitter/libwatchman.png)](http://travis-ci.org/twitter/libwatchman)

This is a C interface to watchman: https://www.github.com/facebook/watchman

You'll need jansson installed in order to use it, and check installed
to run the tests.

Watchman is a wrapper around inotify, kevents, etc.  

Using libwatchman is very straightforward: establish a connection with
watchman_connect, do some commands, then disconnect with
watchman_connection_close. These functions handle memory
management for you.

To set up a watch on a directoy, use watchman_watch.

To make a query, first construct an expression using the
watchman_*_expression functions, then use watchman_do_query. It's OK
to pass in a NULL value for the query parameter.  You have to free
expressions yourself, using watchman_free_expression, but freeing an
expression will free all of its child expressions.

A word of warning: stat fields are only valid for results returned
from watchman.  You can choose these results by specifying flags for
the query.  If you do not specify flags for the query, then you will
only get the default fields: name, exists, newer, size, mode

Memory management:

Watchman makes copies of all strings it has been given. Using the
watchman_free_* functions will free these (as well as any other data
that watchman has allocated).  Watchman never frees anything that it
hasn't created.

## License
Copyright 2014 Twitter, Inc and other contributors

Licensed under the MIT license
