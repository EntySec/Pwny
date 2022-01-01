/*
* MIT License
*
* Copyright (c) 2020-2022 EntySec
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#ifndef JSON_H
#define JSON_H

#include <string.h>
#include <stdlib.h>

#ifndef __cplusplus
typedef char* string;
typedef unsigned char bool;
#define true (1)
#define false (0)
#define TRUE true
#define FALSE false
#endif

#define new(x) (x *) malloc(sizeof(x))
#define newWithSize(x, y) (x *) malloc(y * sizeof(x))
#define renewWithSize(x, y, z) (y *) realloc(x, z * sizeof(y))
#define isWhitespace(x) x == '\r' || x == '\n' || x == '\t' || x == ' '
#define removeWhitespace(x) while(isWhitespace(*x)) x++
#define removeWhitespaceCalcOffset(x, y) while(isWhitespace(*x)) { x++; y++; }

typedef char character;

struct _jsonobject;
struct _jsonpair;
union _jsonvalue;

typedef enum {
    JSON_STRING = 0,
    JSON_OBJECT
} JSONValueType;

typedef struct _jsonobject {
    struct _jsonpair *pairs;
    int count;
} JSONObject;

typedef struct _jsonpair {
    string key;
    union _jsonvalue *value;
    JSONValueType type;
} JSONPair;

typedef union _jsonvalue {
    string stringValue;
    struct _jsonobject *jsonObject;
} JSONValue;

JSONObject *parseJSON(string);
void freeJSONFromMemory(JSONObject *);
char *find_json(JSONObject *, char *);

#endif /* _JSON_H_ */
