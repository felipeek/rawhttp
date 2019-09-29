# rawhttp

Single-file library to create a http server for Linux.

## Example

```C
#define RAWHTTP_IMPLEMENTATION
#include "rawhttp.h"

void root_handle(const void* connection, const rawhttp_request* request, rawhttp_response* response)
{
	char buf[] = "<h1>Welcome to rawhttp server!</h1>";
	response->response_content = buf;
	response->response_content_size = sizeof(buf) - 1;
	response->status_code = 200;
	rawhttp_response_flush(connection, response);
}

int main()
{
	rawhttp_server server;
	rawhttp_server_init(&server, 8080);
	rawhttp_server_register_handle(&server, "/", sizeof("/") - 1, root_handle);
	rawhttp_server_listen(&server);
	return 0;
}
```

## Usage

Just include `rawhttp.h` in your project. You must `#define RAWHTTP_IMPLEMENTATION` once in one of your source files. Please be sure to define before including the header.

The goal of `rawhttp` is to be extremely simple and easy to use. To open a server, you will always:

1. Call `rawhttp_server_init` to initialize a `rawhttp_server` struct.
2. Implement a callback function for each handle you want to register.
3. Call `rawhttp_server_register_handle` for each handle you decided to register.
4. Call `rawhttp_server_listen` to start listening.
5. For a more *serious* implementation, call `rawhttp_server_destroy` to stop the server and release resources.

To avoid duplicate documentation, all functions are documented directly in the source code. However, one can understand the library completely just by looking at the code snippets showed this document.

## How it works?

`rawhttp` opens a socket in the specified port and wait for connections. For each new connection, `rawhttp` creates a new thread and waits for a HTTP request. When the request is received, `rawhttp` parses it, and sends it to the correct handler, based on its URI. Sending it to the correct handler means calling the callback you registered. Inside the callback, `rawhttp_response_flush` should be called, making `rawhttp` send the response the the client. Finally, `rawhttp` closes the connection.

## A complete example

```C
#define RAWHTTP_IMPLEMENTATION
#include "rawhttp.h"
#include <signal.h>

rawhttp_server server;

void root_handle(const void* connection, const rawhttp_request* request, rawhttp_response* response)
{
	// Just for fun, we check if we received the header Secret-Header:Secret-Value
	char secret_header[] = "Secret-Header";
	char secret_header_expected_value[] = "Secret-Value";
	const rawhttp_header_value* secret_header_value = rawhttp_header_get(&request->header, secret_header, sizeof(secret_header) - 1);
	if (secret_header_value != NULL && sizeof(secret_header_expected_value) - 1 == secret_header_value->value_size && !strncmp(secret_header_value->value, secret_header_expected_value, sizeof(secret_header_expected_value) - 1))
	{
		// If we received this header, we send this secret response
		char buf[] = "<h1>You used the secret header!</h1>";
		response->response_content = buf;
		response->response_content_size = sizeof(buf) - 1;

		// And also set a secret response header
		char secret_response_header[] = "Secret-Response-Header";
		char secret_response_header_value[] = "Secret-Value";
		rawhttp_response_add_header(response, secret_response_header, sizeof(secret_response_header) - 1, secret_response_header_value, sizeof(secret_response_header_value) - 1);
		response->status_code = 200;
		rawhttp_response_flush(connection, response);
	}
	else
	{
		// If the secret header was not sent, we send the default response.
		char buf[] = "<h1>Welcome to rawhttp server!</h1>";
		response->response_content = buf;
		response->response_content_size = sizeof(buf) - 1;
		response->status_code = 200;
		rawhttp_response_flush(connection, response);
	}
}

void foo_handle(const void* connection, const rawhttp_request* request, rawhttp_response* response)
{
	char buf[] = "<h1>FOO!</h1>";
	response->response_content = buf;
	response->response_content_size = sizeof(buf) - 1;
	response->status_code = 200;
	rawhttp_response_flush(connection, response);
}

void foo2_handle(const void* connection, const rawhttp_request* request, rawhttp_response* response)
{
	char buf[] = "<h1>FOO2!</h1>";
	response->response_content = buf;
	response->response_content_size = sizeof(buf) - 1;
	response->status_code = 200;
	rawhttp_response_flush(connection, response);
}

void close_server(int signum)
{
	// Stops the server and releases resources
	rawhttp_server_destroy(&server);
}

int main()
{
	signal(SIGINT, close_server);

	// Makes rawhttp redirect its logs to stderr
	rawhttp_log_stream = stderr;

	rawhttp_server_init(&server, 8080);

	// Register a handle for pattern '/'. This will basically receive all requests
	// that doesn't have a "more specific" handler assigned.
	rawhttp_server_register_handle(&server, "/", sizeof("/") - 1, root_handle);
	// Register a handle for pattern '/foo/'. This will receive all requests
	// which URI has the format /foo/*. (example: /foo/ , /foo/bar , /foo/bar/daz)
	rawhttp_server_register_handle(&server, "/foo/", sizeof("/foo/") - 1, foo_handle);
	// Register a handle for the specific URI '/foo2'. This will receive only requests
	// with this specific URI. This happens because it doesn't end with a slash.
	rawhttp_server_register_handle(&server, "/foo2", sizeof("/foo2") - 1, foo2_handle);

	// In this example,
	// '/', '/a', '/foo', '/foo2/' and '/foo2/bar' are all redirected to handle 1
	// '/foo/', '/foo/a', '/foo/a/b/' are all redirected to handle 2
	// only '/foo2' is redirected to handle 3

	// Starts the server. This blocks!
	rawhttp_server_listen(&server);

	return 0;
}
```

## License

This project is licensed under the terms of the MIT license.