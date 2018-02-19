#pragma once
#include "net/sys.h"

class parser
{
public:
	uint8_t   *_data;
	uintptr_t  _size;
	uintptr_t  _valid;

public:
	parser(const void *lpdata, uintptr_t nsize) : _data(static_cast<uint8_t *>(const_cast<void *>(lpdata))), _size(nsize), _valid(1) {
	}

public:
	parser &push(uintptr_t s) {
		this->_data += s;
		this->_size -= s;
		return *this;
	}
	parser &pop(uintptr_t s) {
		this->_data -= s;
		this->_size += s;
		return *this;
	}
	template<typename _Type> _Type *get() {
		if (this->_valid && this->_size >= sizeof(_Type)) {
			auto p = reinterpret_cast<_Type *>(this->_data);
			this->push(sizeof(_Type));
			return p;
		} //if
		this->_valid = 0;
		return nullptr;
	}
	template<typename _Type> _Type *peek() {
		if (this->_size >= sizeof(_Type)) {
			return reinterpret_cast<_Type *>(this->_data);
		} //if
		return nullptr;
	}
};