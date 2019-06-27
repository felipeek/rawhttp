#include <stdio.h>

#define HTTP_STATUS_CONTINUE "100"
#define HTTP_STATUS_OK "200"
#define HTTP_STATUS_CREATED "201"
#define HTTP_STATUS_BAD_REQUEST "400"
#define HTTP_STATUS_UNAUTHORIZED "401"
#define HTTP_STATUS_FORBIDDEN "403"
#define HTTP_STATUS_NOT_FOUND "404"
#define HTTP_STATUS_METHOD_NOT_ALLOWED "405"
#define HTTP_STATUS_INTERNAL_SERVER_ERROR "500"
#define HTTP_STATUS_NOT_IMPLEMENTED "501"
#define HTTP_STATUS_SERVICE_NOT_AVAILABLE "503"

typedef enum
{
	HTTP_GET,
	HTTP_HEAD,
	HTTP_POST,
	HTTP_PUT,
	HTTP_DELETE,
	HTTP_TRACE,
	HTTP_OPTIONS,
	HTTP_CONNECT,
	HTTP_PATCH
} rawhttp_method;

typedef struct
{
	void* elements;
	long long capacity;
	long long element_size;
} rawhttp_hash_table;

typedef struct
{
	rawhttp_hash_table ht;
} rawhttp_header;

typedef struct {
	rawhttp_method method;
	const char* data;
	const char* uri;
	long long uri_size;
	rawhttp_header header;
	int connected_socket;
} rawhttp_request;

typedef struct {
	const char* header;
	long long header_size;
	const char* value;
	long long value_size;
} rawhttp_response_header;

typedef struct {
	rawhttp_response_header* headers;
	long long headers_size;
	long long headers_capacity;
	char* response_content;
	long long response_content_size;
	char* status_code;
} rawhttp_response;

// function that the client will create to handle requests for a specific path
typedef void (*rawhttp_server_handle_func)(const void* connection, const rawhttp_request* request, rawhttp_response* response);

typedef struct {
	rawhttp_server_handle_func handle;
} rawhttp_server_handler;

typedef struct {
	rawhttp_server_handler handler;
	int valid;
	int has_handler;
	int subtree_root;
	const char* pattern;
	long long pattern_size;
	long long next;
	long long child;
} rawhttp_handler_tree_element;

typedef struct {
	rawhttp_handler_tree_element* elements;
	long long num_elements;
	long long capacity;
} rawhttp_handler_tree;

typedef struct {
	int sockfd;
	int port;
	rawhttp_handler_tree handlers;
} rawhttp_server;

typedef struct
{
	const char* value;
	long long value_size;
} rawhttp_header_value;

typedef enum {
	RAWHTTP_LISTEN_ERROR = 1,
	RAWHTTP_ACCEPT_ERROR = 2,
	RAWHTTP_THREAD_ERROR = 3,
	RAWHTTP_BIND_ERROR = 4,
	RAWHTTP_CREATE_ERROR = 5,
	RAWHTTP_HANDLER_TREE_PATTERN_ALREADY_REGISTERED_ERROR = 6,
	RAWHTTP_PARSER_READ_ERROR = 7,
	rawhttp_ht_hash_TABLE_CREATE_ERROR = 8,
	rawhttp_ht_hash_TABLE_PUT_ALREADY_EXISTS_ERROR = 9
} rawhttp_error_code;

int rawhttp_error;
FILE* rawhttp_log_stream;

int rawhttp_server_init(rawhttp_server* server, int port);
// @TODO: implement server stop/destroy
int rawhttp_server_register_handle(rawhttp_server* server, const char* pattern, long long pattern_size, rawhttp_server_handle_func handle);
int rawhttp_server_listen(rawhttp_server* server);
void rawhttp_response_add_header(rawhttp_response* response, const char* header, long long header_size, const char* value, long long value_size);
const rawhttp_header_value* rawhttp_header_get(const rawhttp_header* http_header, const char* request_field, long long request_field_size);
ssize_t rawhttp_response_flush(const void* _connection, rawhttp_response* response);
char* rawhttp_strerror(int rawhttp_error);

/***
 *      _____                 _                           _        _   _             
 *     |_   _|               | |                         | |      | | (_)            
 *       | |  _ __ ___  _ __ | | ___ _ __ ___   ___ _ __ | |_ __ _| |_ _  ___  _ __  
 *       | | | '_ ` _ \| '_ \| |/ _ \ '_ ` _ \ / _ \ '_ \| __/ _` | __| |/ _ \| '_ \ 
 *      _| |_| | | | | | |_) | |  __/ | | | | |  __/ | | | || (_| | |_| | (_) | | | |
 *     |_____|_| |_| |_| .__/|_|\___|_| |_| |_|\___|_| |_|\__\__,_|\__|_|\___/|_| |_|
 *                     | |                                                           
 *                     |_|                                                           
 */

// BIG LETTERS: http://patorjk.com/software/taag/#p=display&c=c&f=Big&t=rawhttp%0A

#ifdef RAWHTTP_IMPLEMENTATION
#include <stdlib.h>
#include <stdarg.h>
#include <memory.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

typedef struct {
	rawhttp_server* server;
	struct sockaddr_in client_address;
	int connected_socket;
} rawhttp_connection;

#define true 1
#define false 0

/***
 *      _                       _             
 *     | |                     (_)            
 *     | |     ___   __ _  __ _ _ _ __   __ _ 
 *     | |    / _ \ / _` |/ _` | | '_ \ / _` |
 *     | |___| (_) | (_| | (_| | | | | | (_| |
 *     |______\___/ \__, |\__, |_|_| |_|\__, |
 *                   __/ | __/ |         __/ |
 *                  |___/ |___/         |___/ 
 */

char* rawhttp_strerror(int rawhttp_error)
{
	switch (rawhttp_error)
	{
		default: return "No error message was provided";
		case RAWHTTP_LISTEN_ERROR: return "Error listening for socket connections (check errno for details)";
		case RAWHTTP_ACCEPT_ERROR: return "Error accepting socket connection (check errno for details)";
		case RAWHTTP_THREAD_ERROR: return "Error creating thread for new connection (check errno for details)";
		case RAWHTTP_BIND_ERROR: return "Error binding socket (check errno for details)";
		case RAWHTTP_CREATE_ERROR: return "Error creating socket (check errno for details)";
		case RAWHTTP_HANDLER_TREE_PATTERN_ALREADY_REGISTERED_ERROR: return "Error registering new pattern in handler tree: already registered";
		case RAWHTTP_PARSER_READ_ERROR: return "Error reading next chunk of bytes from socket";
		case rawhttp_ht_hash_TABLE_CREATE_ERROR: return "Error creating new hash table (out of memory?)";
		case rawhttp_ht_hash_TABLE_PUT_ALREADY_EXISTS_ERROR: return "Error putting new element to hash table: already exists";
	}
}

void rawhttp_log(char* message, ...)
{
	// @TODO: this must be thread safe!
	if (rawhttp_log_stream)
	{
		fprintf(stderr, "rawhttp: ");
		va_list argptr;
		va_start(argptr, message);
		vfprintf(stderr, message, argptr);
		va_end(argptr);
		fprintf(stderr, "\n");
	}
}

/***
 *      _    _           _       _______    _     _      
 *     | |  | |         | |     |__   __|  | |   | |     
 *     | |__| | __ _ ___| |__      | | __ _| |__ | | ___ 
 *     |  __  |/ _` / __| '_ \     | |/ _` | '_ \| |/ _ \
 *     | |  | | (_| \__ \ | | |    | | (_| | |_) | |  __/
 *     |_|  |_|\__,_|___/_| |_|    |_|\__,_|_.__/|_|\___|
 *                                                       
 *                                                       
 */

typedef struct
{
	const char* key;
	long long key_size;
	int valid;
} rawhttp_ht_hash_table_element;

static int rawhttp_ht_grow(rawhttp_hash_table* ht, long long new_capacity);

static unsigned long long rawhttp_ht_hash(const char* str, long long str_size)
{
	unsigned long long hash = 5381;
	long long c;

	for (; str_size > 0; --str_size)
	{
		c = *str++;
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return hash;
}

static rawhttp_ht_hash_table_element* rawhttp_ht_get_element_on_index(const rawhttp_hash_table* ht, long long index)
{
	return (rawhttp_ht_hash_table_element*)((unsigned char*)ht->elements + index * (sizeof(rawhttp_ht_hash_table_element) + ht->element_size));
}

static void* rawhttp_ht_get_value_on_index(const rawhttp_hash_table* ht, long long index)
{
	return (void*)((unsigned char*)ht->elements + index * (sizeof(rawhttp_ht_hash_table_element) + ht->element_size) + sizeof(rawhttp_ht_hash_table_element));
}

static void rawhttp_ht_put_element_on_index(const rawhttp_hash_table* ht, long long index, rawhttp_ht_hash_table_element* element)
{
	*(rawhttp_ht_hash_table_element*)((unsigned char*)ht->elements + index * (sizeof(rawhttp_ht_hash_table_element) + ht->element_size)) = *element;
}

static void rawhttp_ht_put_value_on_index(const rawhttp_hash_table* ht, long long index, const void* value)
{
	memcpy(((unsigned char*)ht->elements + index * (sizeof(rawhttp_ht_hash_table_element) + ht->element_size) + sizeof(rawhttp_ht_hash_table_element)), value, ht->element_size);
}

static int rawhttp_ht_hash_table_create(rawhttp_hash_table* ht, long long capacity, long long element_size)
{
	ht->elements = calloc(capacity, sizeof(rawhttp_ht_hash_table_element) + element_size);
	if (!ht->elements)
	{
		rawhttp_error = rawhttp_ht_hash_TABLE_CREATE_ERROR;
		rawhttp_log(rawhttp_strerror(rawhttp_error));
		return -1;
	}
	ht->capacity = capacity;
	ht->element_size = element_size;

	return 0;
}

static const void* rawhttp_ht_hash_table_get(const rawhttp_hash_table* ht, const char* key, long long key_size)
{
	unsigned long long requested_key_hash = rawhttp_ht_hash(key, key_size);
	long long hash_table_position = requested_key_hash % ht->capacity;
	long long positions_scanned = 0;

	while (positions_scanned < ht->capacity)
	{
		rawhttp_ht_hash_table_element* current_element = rawhttp_ht_get_element_on_index(ht, hash_table_position);
		// Test if the current field has content
		if (!current_element->valid)
			break;
		// Test if the key is equal
		if (key_size != current_element->key_size || !strncmp(key, current_element->key, key_size))
			return rawhttp_ht_get_value_on_index(ht, hash_table_position);
		// If the key is not equal, we check if the hash is equal... If it is, we shall keep searching
		if (requested_key_hash != rawhttp_ht_hash(current_element->key, current_element->key_size))
			break;

		hash_table_position = (hash_table_position + 1) % ht->capacity;
		++positions_scanned;
	}

	return NULL;
}

static int rawhttp_ht_hash_table_put(rawhttp_hash_table* ht, const char* key, long long key_size, const void* value)
{
	unsigned long long requested_key_hash = rawhttp_ht_hash(key, key_size);
	long long hash_table_position = requested_key_hash % ht->capacity;
	long long positions_scanned = 0;

	while (positions_scanned < ht->capacity)
	{
		rawhttp_ht_hash_table_element* current_element = rawhttp_ht_get_element_on_index(ht, hash_table_position);
		// Test if the current field has content
		if (!current_element->valid)
		{
			current_element->key = key;
			current_element->key_size = key_size;
			current_element->valid = true;
			rawhttp_ht_put_element_on_index(ht, hash_table_position, current_element);
			rawhttp_ht_put_value_on_index(ht, hash_table_position, value);
			return 0;
		}
		else
		{
			// Just for safety, we check if the key is the same to throw an error
			if (key_size == current_element->key_size && strncmp(key, current_element->key, key_size))
			{
				rawhttp_error = rawhttp_ht_hash_TABLE_PUT_ALREADY_EXISTS_ERROR;
				rawhttp_log(rawhttp_strerror(rawhttp_error));
				return -1;
			}
		}

		hash_table_position = (hash_table_position + 1) % ht->capacity;
		++positions_scanned;
	}

	if (rawhttp_ht_grow(ht, 2 * ht->capacity))
		return -1;

	return rawhttp_ht_hash_table_put(ht, key, key_size, value);
}

static int rawhttp_ht_grow(rawhttp_hash_table* ht, long long new_capacity)
{
	rawhttp_hash_table old_ht = *ht;

	if (rawhttp_ht_hash_table_create(ht, new_capacity, old_ht.element_size))
		return -1;

	for (long long i = 0; i < old_ht.capacity; ++i)
	{
		rawhttp_ht_hash_table_element* current_element = rawhttp_ht_get_element_on_index(&old_ht, i);
		void* current_value = rawhttp_ht_get_value_on_index(&old_ht, i);
		if (current_element->valid)
			if (rawhttp_ht_hash_table_put(ht, current_element->key, current_element->key_size, current_value))
				return -1;
	}

	// Manually delete old hash table
	free(old_ht.elements);

	return 0;
}

static int rawhttp_ht_hash_table_destroy(rawhttp_hash_table* ht)
{
	free(ht->elements);
	return 0;
}

/***
 *      _    _ _______ _______ _____    _____                                      
 *     | |  | |__   __|__   __|  __ \  |  __ \                                     
 *     | |__| |  | |     | |  | |__) | | |__) |___  ___ _ __   ___  _ __  ___  ___ 
 *     |  __  |  | |     | |  |  ___/  |  _  // _ \/ __| '_ \ / _ \| '_ \/ __|/ _ \
 *     | |  | |  | |     | |  | |      | | \ \  __/\__ \ |_) | (_) | | | \__ \  __/
 *     |_|  |_|  |_|     |_|  |_|      |_|  \_\___||___/ .__/ \___/|_| |_|___/\___|
 *                                                     | |                         
 *                                                     |_|                         
 */

typedef struct {
	char* buffer;
	long long size;
	long long capacity;
} rawhttp_response_dynamic_buffer;

int rawhttp_response_new(rawhttp_response* response)
{
	response->headers_size = 0;
	response->headers_capacity = 32;
	response->headers = calloc(response->headers_capacity, sizeof(rawhttp_response_header));
	response->status_code = HTTP_STATUS_OK;
	return 0;
}

int rawhttp_response_destroy(rawhttp_response* response)
{
	free(response->headers);
	return 0;
}

void rawhttp_response_add_header(rawhttp_response* response, const char* header, long long header_size, const char* value, long long value_size)
{
	if (response->headers_capacity == response->headers_size)
	{
		long long new_capacity = response->headers_capacity * 2;
		response->headers = realloc(response->headers, new_capacity);
		response->headers_capacity = new_capacity;
	}

	rawhttp_response_header rh;
	rh.header = header;
	rh.header_size = header_size;
	rh.value = value;
	rh.value_size = value_size;

	response->headers[response->headers_size++] = rh;
}

static void rawhttp_response_dynamic_buffer_add(rawhttp_response_dynamic_buffer* db, const char* msg, long long msg_size)
{
	while (db->size + msg_size + 1 >= db->capacity)
	{
		db->buffer = realloc(db->buffer, 2 * db->capacity);
		db->capacity *= 2;
	}

	memcpy(db->buffer + db->size, msg, msg_size);
	(db->buffer)[db->size + msg_size + 1] = '\0';
	db->size += msg_size;
}

ssize_t rawhttp_response_flush(const void* _connection, rawhttp_response* response)
{
	#define CONTENT_LENGTH_HEADER "Content-Length"
	const rawhttp_connection* connection = (rawhttp_connection*)_connection;

	char buffer[64];
	char content_length_buffer[64];
	int content_length_buffer_written = sprintf(content_length_buffer, "%lld", response->response_content_size);
	rawhttp_response_add_header(response, CONTENT_LENGTH_HEADER, sizeof(CONTENT_LENGTH_HEADER) - 1,
		content_length_buffer, content_length_buffer_written);

	rawhttp_response_dynamic_buffer headers_db;
	headers_db.buffer = calloc(1, 1024);
	headers_db.capacity = 1024;
	headers_db.size = 0;

	int status_line_written = sprintf(buffer, "HTTP/1.1 %s\r\n", response->status_code);
	rawhttp_response_dynamic_buffer_add(&headers_db, buffer, status_line_written);

	for (long long i = 0; i < response->headers_size; ++i)
	{
		rawhttp_response_header* rh = &response->headers[i];
		rawhttp_response_dynamic_buffer_add(&headers_db, rh->header, rh->header_size);
		rawhttp_response_dynamic_buffer_add(&headers_db, ": ", 2);
		rawhttp_response_dynamic_buffer_add(&headers_db, rh->value, rh->value_size);
		rawhttp_response_dynamic_buffer_add(&headers_db, "\r\n", 2);
	}

	rawhttp_response_dynamic_buffer_add(&headers_db, "\r\n", 2);

	struct iovec iov[2];
	iov[0].iov_base = headers_db.buffer;
	iov[0].iov_len = headers_db.size;
	iov[1].iov_base = response->response_content;
	iov[1].iov_len = response->response_content_size;

	ssize_t written = writev(connection->connected_socket, iov, 2);

	free(headers_db.buffer);

	return written;
}

/***
 *      _    _ _______ _______ _____    _    _                _           
 *     | |  | |__   __|__   __|  __ \  | |  | |              | |          
 *     | |__| |  | |     | |  | |__) | | |__| | ___  __ _  __| | ___ _ __ 
 *     |  __  |  | |     | |  |  ___/  |  __  |/ _ \/ _` |/ _` |/ _ \ '__|
 *     | |  | |  | |     | |  | |      | |  | |  __/ (_| | (_| |  __/ |   
 *     |_|  |_|  |_|     |_|  |_|      |_|  |_|\___|\__,_|\__,_|\___|_|   
 *                                                                        
 *                                                                        
 */

static int rawhttp_header_create(rawhttp_header* http_header, unsigned long long capacity)
{
	return rawhttp_ht_hash_table_create(&http_header->ht, capacity, sizeof(rawhttp_header_value));
}

const rawhttp_header_value* rawhttp_header_get(const rawhttp_header* http_header, const char* request_field, long long request_field_size)
{
	return rawhttp_ht_hash_table_get(&http_header->ht, request_field, request_field_size);
}

static int rawhttp_header_put(rawhttp_header* http_header, const char* request_field, long long request_field_size, const char* value, long long value_size)
{
	rawhttp_header_value rhv;
	rhv.value = value;
	rhv.value_size = value_size;
	return rawhttp_ht_hash_table_put(&http_header->ht, request_field, request_field_size, &rhv);
}

static int rawhttp_header_destroy(rawhttp_header* http_header)
{
	return rawhttp_ht_hash_table_destroy(&http_header->ht);
}

/***
 *      _____                         
 *     |  __ \                        
 *     | |__) |_ _ _ __ ___  ___ _ __ 
 *     |  ___/ _` | '__/ __|/ _ \ '__|
 *     | |  | (_| | |  \__ \  __/ |   
 *     |_|   \__,_|_|  |___/\___|_|   
 *                                    
 *                                    
 */

#define RAWHTTP_PARSER_CHUNK_SIZE 1
#define RAWHTTP_PARSER_BUFFER_INITIAL_SIZE 1 // Must be greater than RAWHTTP_PARSER_CHUNK_SIZE
#define RAWHTTP_PARSER_REQUEST_HEADER_DEFAULT_CAPACITY 16

typedef struct {
	char* buffer;
	long long buffer_size;
	long long buffer_end;
	long long buffer_position;
	long long header_size;
} rawhttp_parser_header_buffer;

static long long rawhttp_parser_fetch_next_chunk(rawhttp_parser_header_buffer* phb, int connected_socket)
{
	long long size_needed = phb->buffer_end + RAWHTTP_PARSER_CHUNK_SIZE;
	if (size_needed > phb->buffer_size)
	{
		phb->buffer = realloc(phb->buffer, size_needed);
		phb->buffer_size = size_needed;
	}

	long long size_read;
	if ((size_read = read(connected_socket, phb->buffer + phb->buffer_end, RAWHTTP_PARSER_CHUNK_SIZE)) < 0)
	{
		rawhttp_error = RAWHTTP_PARSER_READ_ERROR;
		rawhttp_log(rawhttp_strerror(rawhttp_error));
		return -1;
	}
	if (size_read == 0)
	{
		// TODO
		rawhttp_log("TODO ...");
		return -1;
	}
	phb->buffer_end += size_read;

	rawhttp_log("Fetched %d bytes from client.", size_read);
	return size_read;
}

// lets make rawhttp also have this function to make the parser a bit better
static int rawhttp_parser_fetch_next_byte(rawhttp_parser_header_buffer* phb, int connected_socket, char* c)
{
	while (phb->header_size + 1 > phb->buffer_end)
		if (rawhttp_parser_fetch_next_chunk(phb, connected_socket) == -1)
			return -1;

	++phb->header_size;
	*c = phb->buffer[phb->header_size - 1];
	return 0;
}

static int rawhttp_parser_fetch_header(rawhttp_parser_header_buffer* phb, int connected_socket)
{
	char c;

	for (;;)
	{
		if (rawhttp_parser_fetch_next_byte(phb, connected_socket, &c))
			return -1;
		
		if (c == '\r')
		{
			if (rawhttp_parser_fetch_next_byte(phb, connected_socket, &c))
				return -1;

			if (c == '\n')
			{
				if (rawhttp_parser_fetch_next_byte(phb, connected_socket, &c))
					return -1;

				if (c == '\r')
				{
					if (rawhttp_parser_fetch_next_byte(phb, connected_socket, &c))
						return -1;

					if (c == '\n')
						return 0;
				}
			}
		}
	}
}

static int rawhttp_parser_get_next_bytes(rawhttp_parser_header_buffer* phb, long long num, int connected_socket, char** ptr)
{
	if (phb->buffer_position + num > phb->header_size)
		return -1;

	phb->buffer_position += num;
	*ptr = phb->buffer + phb->buffer_position - num;
	return 0;
}

static int rawhttp_parser_get_next_string(rawhttp_parser_header_buffer* phb, int connected_socket, char** string_ptr, long long* string_size)
{
	char* ptr;
	if (rawhttp_parser_get_next_bytes(phb, 1, connected_socket, &ptr))
		return -1;

	while (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')
	{
		if (rawhttp_parser_get_next_bytes(phb, 1, connected_socket, &ptr))
			return -1;
	}

	*string_ptr = ptr;
	*string_size = 0;

	while (*ptr != ' ' && *ptr != '\r' && *ptr != '\n')
	{
		++*string_size;
		if (rawhttp_parser_get_next_bytes(phb, 1, connected_socket, &ptr))
			return -1;
	}

	return 0;
}

static int rawhttp_parser_get_request_header(rawhttp_parser_header_buffer* phb, int connected_socket, char** request_header_ptr,
	long long* request_header_size, char** request_header_value_ptr, long long* request_header_value_size)
{
	char* ptr;
	if (rawhttp_parser_get_next_bytes(phb, 1, connected_socket, &ptr))
		return -1;

	while (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')
	{
		if (rawhttp_parser_get_next_bytes(phb, 1, connected_socket, &ptr))
			return -1;
	}

	*request_header_ptr = ptr;
	*request_header_size = 0;

	while (*ptr != ' ' && *ptr != '\r' && *ptr != '\n' && *ptr != ':')
	{
		++*request_header_size;
		if (rawhttp_parser_get_next_bytes(phb, 1, connected_socket, &ptr))
			return -1;
	}

	// skip 1 byte to make sure that we skip ':', when necessary ... this is necessary when there is no space in header (e.g. header:value)
	if (rawhttp_parser_get_next_bytes(phb, 1, connected_socket, &ptr))
		return -1;

	while (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')
	{
		if (rawhttp_parser_get_next_bytes(phb, 1, connected_socket, &ptr))
			return -1;
	}

	*request_header_value_ptr = ptr;
	*request_header_value_size = 0;

	// For the request header value, we must expect spaces (' ') and colons (':') to be part of the value
	while (*ptr != '\r' && *ptr != '\n')
	{
		++*request_header_value_size;
		if (rawhttp_parser_get_next_bytes(phb, 1, connected_socket, &ptr))
			return -1;
	}

	// the last field must be a '\n'!
	if (rawhttp_parser_get_next_bytes(phb, 1, connected_socket, &ptr))
		return -1;
	if (*ptr != '\n')
	{
		// error!
		return -1;
	}

	return 0;
}

static int rawhttp_parser_end_of_header(rawhttp_parser_header_buffer* phb)
{
	// If there is only two more bytes to reach header_size, they are \r\n
	// thus, there are no more headers to parse
	return phb->header_size == phb->buffer_position + 2;
}

static int rawhttp_parser_header_buffer_create(rawhttp_parser_header_buffer* phb)
{
	phb->buffer = malloc(sizeof(char) * RAWHTTP_PARSER_BUFFER_INITIAL_SIZE);
	if (!phb->buffer) return -1;
	phb->buffer_size = RAWHTTP_PARSER_BUFFER_INITIAL_SIZE;
	phb->buffer_end = 0;
	phb->header_size = 0;
	phb->buffer_position = 0;
	return 0;
}

static void rawhttp_parser_header_buffer_destroy(rawhttp_parser_header_buffer* phb)
{
	free(phb->buffer);
}

static int rawhttp_parser_parse(rawhttp_parser_header_buffer* phb, rawhttp_request* request, int connected_socket)
{
	if (rawhttp_parser_fetch_header(phb, connected_socket))
		return -1;

	request->connected_socket = connected_socket;

	if (rawhttp_header_create(&request->header, RAWHTTP_PARSER_REQUEST_HEADER_DEFAULT_CAPACITY))
		return -1;

	// First we get the HTTP method
	long long http_method_size;
	char* http_method;
	if (rawhttp_parser_get_next_string(phb, connected_socket, &http_method, &http_method_size))
	{
		rawhttp_header_destroy(&request->header);
		return -1;
	}
	
	if (!strncmp(http_method, "GET", http_method_size))
		request->method = HTTP_GET;
	else if (!strncmp(http_method, "HEAD", http_method_size))
		request->method = HTTP_HEAD;
	else if (!strncmp(http_method, "POST", http_method_size))
		request->method = HTTP_POST;
	else if (!strncmp(http_method, "PUT", http_method_size))
		request->method = HTTP_PUT;
	else if (!strncmp(http_method, "DELETE", http_method_size))
		request->method = HTTP_DELETE;
	else if (!strncmp(http_method, "TRACE", http_method_size))
		request->method = HTTP_TRACE;
	else if (!strncmp(http_method, "OPTIONS", http_method_size))
		request->method = HTTP_OPTIONS;
	else if (!strncmp(http_method, "CONNECT", http_method_size))
		request->method = HTTP_CONNECT;
	else if (!strncmp(http_method, "PATCH", http_method_size))
		request->method = HTTP_PATCH;
	else
		request->method = -1;

	// Now we get the URI
	long long uri_size;
	char* uri;
	if (rawhttp_parser_get_next_string(phb, connected_socket, &uri, &uri_size))
	{
		rawhttp_header_destroy(&request->header);
		return -1;
	}
	request->uri = uri;
	request->uri_size = uri_size;

	// Now we get the version
	// Ignore the version for now
	// ...
	long long version_size;
	char* version;
	if (rawhttp_parser_get_next_string(phb, connected_socket, &version, &version_size))
	{
		rawhttp_header_destroy(&request->header);
		return -1;
	}

	// Parse all request header fields
	for (;;)
	{
		if (rawhttp_parser_end_of_header(phb))
			break;
	
		// Get the next request header
		long long request_header_size, request_header_value_size;
		char* request_header;
		char* request_header_value;
		if (rawhttp_parser_get_request_header(phb, connected_socket, &request_header, &request_header_size,
			&request_header_value, &request_header_value_size))
		{
			rawhttp_header_destroy(&request->header);
			return -1;
		}

		rawhttp_log("Received header %.*s = %.*s", request_header_size, request_header, request_header_value_size, request_header_value);

		if (rawhttp_header_put(&request->header, request_header, request_header_size, request_header_value, request_header_value_size))
		{
			rawhttp_header_destroy(&request->header);
			return -1;
		}
	}

	// At this point, we should start parsing the request body.
	// Part of the request body may be already in phb.
	// phb->buffer_end - phb->header_size gives the part of the buffer that is already the request body
	// We should receive a callback from the user and start feeding him the body, beggining by this part, if it exists
	// We must feed the body in chunks, since it may be a big chunk of data
	// This was not implemented yet.

	return 0;
}

/***
 *      _    _                 _ _             _______            
 *     | |  | |               | | |           |__   __|           
 *     | |__| | __ _ _ __   __| | | ___ _ __     | |_ __ ___  ___ 
 *     |  __  |/ _` | '_ \ / _` | |/ _ \ '__|    | | '__/ _ \/ _ \
 *     | |  | | (_| | | | | (_| | |  __/ |       | | | |  __/  __/
 *     |_|  |_|\__,_|_| |_|\__,_|_|\___|_|       |_|_|  \___|\___|
 *                                                                
 *                                                                
 */

#define RAWHTTP_HANDLER_TREE_INVALID_NEXT -1
#define RAWHTTP_HANDLER_TREE_INVALID_CHILD -1

static int rawhttp_handler_tree_create(rawhttp_handler_tree* tree, long long capacity)
{
	tree->elements = calloc(capacity, sizeof(rawhttp_handler_tree_element));
	if (!tree->elements) return -1;
	tree->num_elements = 1;
	tree->capacity = capacity;
	tree->elements[0].has_handler = false;
	tree->elements[0].child = RAWHTTP_HANDLER_TREE_INVALID_CHILD;
	tree->elements[0].next = RAWHTTP_HANDLER_TREE_INVALID_NEXT;
	tree->elements[0].valid = true;
	tree->elements[0].pattern = "/";
	tree->elements[0].pattern_size = 1;
	return 0;
}

static long long rawhttp_handler_tree_pattern_get_levels(const char* pattern, long long pattern_size, int is_subtree_root)
{
	long long levels = 0, pos = 0;
	while (pos < pattern_size)
		if (pattern[pos++] == '/')
			++levels;
	if (!is_subtree_root) ++levels;
	return levels;
}

static long long rawhttp_handler_tree_pattern_get_size_of_level(const char* pattern, long long pattern_size, long long level)
{
	long long size = 0;

	while (level >= 0 && size != pattern_size)
	{
		if (pattern[size] == '/')
		{
			if (level == 0)
			    return ++size;

			--level;
		}
		++size;
	}
	
	return pattern_size;
}

static int rawhttp_handler_tree_grow(rawhttp_handler_tree* tree, long long new_capacity)
{
	tree->elements = realloc(tree->elements, new_capacity * sizeof(rawhttp_handler_tree_element));
	if (tree->elements == NULL) return -1;
	tree->capacity = new_capacity;
	return 0;
}

static int rawhttp_handler_tree_create_element(rawhttp_handler_tree* tree, const char* pattern, long long pattern_size, long long pattern_level, long long pattern_total_levels,
	long long* created_element_root, const rawhttp_server_handler* handler, int is_subtree_root)
{
	rawhttp_handler_tree_element* new_element = NULL;
	rawhttp_handler_tree_element* previous_element = NULL;
	long long new_pattern_split_size;
	*created_element_root = tree->num_elements;

	do
	{
		// Grow tree if necessary
		if (tree->num_elements == tree->capacity)
			if (rawhttp_handler_tree_grow(tree, 2 * tree->capacity))
				return -1;

		new_pattern_split_size = rawhttp_handler_tree_pattern_get_size_of_level(pattern, pattern_size, pattern_level);
		new_element = &tree->elements[tree->num_elements++];
		new_element->child = RAWHTTP_HANDLER_TREE_INVALID_CHILD;
		new_element->has_handler = false;
		new_element->next = RAWHTTP_HANDLER_TREE_INVALID_NEXT;
		new_element->pattern = pattern;
		new_element->pattern_size = new_pattern_split_size;
		new_element->subtree_root = true;
		new_element->valid = true;
		if (previous_element) previous_element->child = tree->num_elements - 1;
		previous_element = new_element;
		++pattern_level;
	}
	while (pattern_level < pattern_total_levels);

	previous_element->subtree_root = is_subtree_root;
	previous_element->handler = *handler;
	previous_element->has_handler = true;
	return 0;
}

static int rawhttp_handler_tree_is_pattern_subtree_root(const char* pattern, long long pattern_size)
{
	return pattern[pattern_size - 1] == '/';
}

static int rawhttp_handler_tree_put(rawhttp_handler_tree* tree, const char* pattern, long long pattern_size, rawhttp_server_handle_func handle)
{
	rawhttp_server_handler handler;
	handler.handle = handle;

	long long pattern_total_levels, pattern_level = 0;
	long long new_pattern_split_size, current_pattern_split_size;
	rawhttp_handler_tree_element* current_element = &tree->elements[0];
	long long created_element_index;
	int is_subtree_root = rawhttp_handler_tree_is_pattern_subtree_root(pattern, pattern_size);

	pattern_total_levels = rawhttp_handler_tree_pattern_get_levels(pattern, pattern_size, is_subtree_root);

	while (true)
	{
		current_pattern_split_size = rawhttp_handler_tree_pattern_get_size_of_level(current_element->pattern, current_element->pattern_size, pattern_level);
		new_pattern_split_size = rawhttp_handler_tree_pattern_get_size_of_level(pattern, pattern_size, pattern_level);
		
		if (new_pattern_split_size == current_pattern_split_size && !strncmp(pattern, current_element->pattern, new_pattern_split_size))
		{
			// Pattern split match!
			if (pattern_level == pattern_total_levels - 1)
			{
				if (current_element->has_handler)
				{
					rawhttp_error = RAWHTTP_HANDLER_TREE_PATTERN_ALREADY_REGISTERED_ERROR;
					rawhttp_log(rawhttp_strerror(rawhttp_error));
					return -1;
				}
				else
				{
					current_element->has_handler = true;
					current_element->handler = handler;
					return 0;
				}
			}
			else if (current_element->child == RAWHTTP_HANDLER_TREE_INVALID_CHILD)
			{
				if (rawhttp_handler_tree_create_element(tree, pattern, pattern_size, pattern_level + 1, pattern_total_levels,
					&created_element_index, &handler, is_subtree_root))
					return -1;
				current_element->child = created_element_index;
				return 0;
			}
			else
			{
				++pattern_level;
				current_element = &tree->elements[current_element->child];
			}
		}
		else
		{
			// Different pattern split
			if (current_element->next == RAWHTTP_HANDLER_TREE_INVALID_NEXT)
			{
				if (rawhttp_handler_tree_create_element(tree, pattern, pattern_size, pattern_level, pattern_total_levels,
					&created_element_index, &handler, is_subtree_root))
					return -1;
				current_element->next = created_element_index;
				return 0;
			}
			else
				current_element = &tree->elements[current_element->next];
		}
	}
}

static const rawhttp_server_handler* rawhttp_handler_tree_get(rawhttp_handler_tree* tree, const char* pattern, long long pattern_size)
{
	long long pattern_total_levels, pattern_level = 0;
	long long new_pattern_split_size, current_pattern_split_size;
	rawhttp_handler_tree_element* current_element = &tree->elements[0];
	int is_subtree_root = rawhttp_handler_tree_is_pattern_subtree_root(pattern, pattern_size);
	rawhttp_server_handler* handler = NULL;

	pattern_total_levels = rawhttp_handler_tree_pattern_get_levels(pattern, pattern_size, is_subtree_root);

	while (true)
	{
		current_pattern_split_size = rawhttp_handler_tree_pattern_get_size_of_level(current_element->pattern, current_element->pattern_size, pattern_level);
		new_pattern_split_size = rawhttp_handler_tree_pattern_get_size_of_level(pattern, pattern_size, pattern_level);
		
		if (new_pattern_split_size == current_pattern_split_size && !strncmp(pattern, current_element->pattern, new_pattern_split_size))
		{
			if (current_element->has_handler)
				handler = &current_element->handler;

			// Pattern split match!
			if (pattern_level == pattern_total_levels - 1 || current_element->child == RAWHTTP_HANDLER_TREE_INVALID_CHILD)
				break;
			else
			{
				++pattern_level;
				current_element = &tree->elements[current_element->child];
			}
		}
		else
		{
			// Different pattern split
			if (current_element->next == RAWHTTP_HANDLER_TREE_INVALID_NEXT)
				break;
			else
				current_element = &tree->elements[current_element->next];
		}
	}

	return handler;
}

/***
 *       _____                          
 *      / ____|                         
 *     | (___   ___ _ ____   _____ _ __ 
 *      \___ \ / _ \ '__\ \ / / _ \ '__|
 *      ____) |  __/ |   \ V /  __/ |   
 *     |_____/ \___|_|    \_/ \___|_|   
 *                                      
 *                                      
 */

#define RAWHTTP_SERVER_MAX_QUEUE_SERVER_PENDING_CONNECTIONS 5

int rawhttp_server_init(rawhttp_server* server, int port)
{
	if (rawhttp_handler_tree_create(&server->handlers, 16 /* change me */))
		return -1;

	server->sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// workaround for dev purposes (avoiding error binding socket: Address already in use)
	int option = 1;
	setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

	option = 1;
	setsockopt(server->sockfd, IPPROTO_TCP, TCP_NODELAY, &option, sizeof(option));


	if (server->sockfd == -1)
	{
		rawhttp_error = RAWHTTP_CREATE_ERROR;
		rawhttp_log("Error creating socket: %s", strerror(errno));
		return -1;
	}

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(struct sockaddr_in));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(port);

	if (bind(server->sockfd, (struct sockaddr*)&server_address, sizeof(server_address)) == -1)
	{
		rawhttp_error = RAWHTTP_BIND_ERROR;
		rawhttp_log("Error binding socket: %s", strerror(errno));
		return -1;
	}

	server->port = port;

	return 0;
}

int rawhttp_server_register_handle(rawhttp_server* server, const char* pattern, long long pattern_size, rawhttp_server_handle_func handle)
{
	return rawhttp_handler_tree_put(&server->handlers, pattern, pattern_size, handle);
}

static void* rawhttp_server_new_connection_callback(void* arg)
{
	rawhttp_connection* connection = (rawhttp_connection*)arg;
	char* client_ip_ascii = inet_ntoa(connection->client_address.sin_addr);
	rawhttp_log("Accepted connection from client %s", client_ip_ascii);

	for (;;)
	{
		rawhttp_request request;
		rawhttp_parser_header_buffer phb;
		if (rawhttp_parser_header_buffer_create(&phb))
		{
			rawhttp_log("Error creating parsing buffer");
			break;
		}
		if (rawhttp_parser_parse(&phb, &request, connection->connected_socket))
		{
			rawhttp_log("Error parsing HTTP packet. Connection was dropped or syntax was invalid");
			rawhttp_log("Connection with client %s will be destroyed", client_ip_ascii);
			rawhttp_parser_header_buffer_destroy(&phb);
			break;
		}

		const rawhttp_server_handler* handler = rawhttp_handler_tree_get(&connection->server->handlers, request.uri, request.uri_size);
		if (handler)
		{
			rawhttp_response response;
			if (rawhttp_response_new(&response))
			{
				rawhttp_log("Error creating new rawhttp_response");
				rawhttp_header_destroy(&request.header);
				rawhttp_parser_header_buffer_destroy(&phb);
				break;
			}
			handler->handle(connection, &request, &response);
			if (rawhttp_response_destroy(&response))
			{
				rawhttp_log("Error destroying rawhttp_response");
				rawhttp_header_destroy(&request.header);
				rawhttp_parser_header_buffer_destroy(&phb);
				break;
			}
		}
		else
		{
			char buf[] = "HTTP/1.0 404 Not Found\n"
				"Connection: Keep-Alive\n"
				"Content-Length: 9\n"
				"\n"
				"404 Error";
			write(request.connected_socket, buf, sizeof(buf) - 1);
		}

		// dealloc request
		rawhttp_header_destroy(&request.header);
		rawhttp_parser_header_buffer_destroy(&phb);
	}

	close(connection->connected_socket);
	free(connection);
	rawhttp_log("Destroyed connection from client %s", client_ip_ascii);
	return NULL;
}

int rawhttp_server_listen(rawhttp_server* server)
{
	if (listen(server->sockfd, RAWHTTP_SERVER_MAX_QUEUE_SERVER_PENDING_CONNECTIONS) == -1)
	{
		rawhttp_error = RAWHTTP_LISTEN_ERROR;
		rawhttp_log("Error listening for socket connections: %s", strerror(errno));
		return -1;
	}

	struct sockaddr_in client_address;

	while (1)
	{
		socklen_t client_address_length = sizeof(client_address);
		int connected_socket = accept(server->sockfd, (struct sockaddr*)&client_address, &client_address_length);
		if (connected_socket == -1)
		{
			rawhttp_error = RAWHTTP_ACCEPT_ERROR;
			rawhttp_log("Error accepting socket connection: %s", strerror(errno));
			return -1;
		}

		pthread_t connection_thread;
		rawhttp_connection* connection = malloc(sizeof(rawhttp_connection));
		connection->server = server;
		connection->connected_socket = connected_socket;
		connection->client_address = client_address;
		if (pthread_create(&connection_thread, NULL, rawhttp_server_new_connection_callback, connection))
		{
			rawhttp_error = RAWHTTP_THREAD_ERROR;
			rawhttp_log("Error creating thread for new connection: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}
#endif