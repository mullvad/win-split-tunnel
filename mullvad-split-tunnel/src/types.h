#pragma once

//
// types.h
//
// Used to resolve dependencies between public.h/shared.h
//

#define ST_POOL_TAG 'UTPS'

enum class ST_PAGEABLE
{
	YES = 0,
	NO
};

//
// Type-safety when passing around lower case device paths.
// Same definition as UNICODE_STRING so they can be cast between.
//
typedef struct tag_LOWER_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
}
LOWER_UNICODE_STRING;
