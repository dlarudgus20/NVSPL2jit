// Copyright (c) 2015, 임경현
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met :
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and / or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "stdafx.h"

#include "output.h"

// 최적화를 위해 data의 수정을 lazy eval하는 자료구조와 함수
struct ModifyInfo
{
	bool isModified;		// default: false
	bool isRelative;		// default: true
	bool isLoadedOnEax;
	int32_t value;

	void clear()
	{
		isModified = false;
		isRelative = true;
	}
	void go_modifying()
	{
		if (!isModified)
		{
			value = 0;
			isModified = true;
		}
		isLoadedOnEax = false;
	}
};
// bSaveToEax == true인 경우 수정된 data를 eax에 저장
// mi.isModified == false라도 eax에 data가 있음을 보장.
// 단, 컴파일타임에 값을 알 수 있을 경우 eax에 저장이 안되고 mi.isLoadedOnEax의 값이 false가 됨.
uint8_t *ApplyModify(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi, bool bSaveToEax);

// 스크립트 명령 컴파일 함수
typedef uint8_t *(*cmd_func_type)(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);

uint8_t *cmd_ForwardBack(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);
uint8_t *cmd_PlusMinus(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);
uint8_t *cmd_Integer(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);
uint8_t *cmd_Character(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);
uint8_t *cmd_Real(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);
uint8_t *cmd_Space(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);
uint8_t *cmd_Enter(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);
uint8_t *cmd_O_init(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);
uint8_t *cmd_label(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);
uint8_t *cmd_label_jmp(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);
uint8_t *cmd_Quit(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi);

inline uint32_t get_displacement(uint8_t *c, void *addr)
{
	return (uint32_t)addr - (uint32_t)c;
}

int my_fgetc(FILE *file);
void my_ungetc(char ch);
int read_int(FILE *file, int *i);

int main(int argc, char *argv[])
{
#ifdef _DEBUG
	atexit([] { getchar(); });
#endif

	char *output_file = nullptr;
	bool bQuiet = false;

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s [nvs file] (options)\n", argv[0]);
		return -1;
	}

	for (int i = 2; i < argc; i++)
	{
		if (strcmp(argv[0], "-output") == 0)
		{
			if (++i >= argc || output_file != nullptr)
			{
				fprintf(stderr, "argument syntax error\n");
				return -1;
			}
			output_file = argv[i];
		}
		else if (strcmp(argv[0], "-quiet") == 0)
		{
			if (bQuiet)
			{
				fprintf(stderr, "argument syntax error\n");
				return -1;
			}
			bQuiet = true;
		}
	}

	if (!bQuiet)
		puts("NVSPL2jit 1.1 - NVSPL2 Script Optimize JIT Compiler made by 암겨혀\n");

	FILE *file = fopen(argv[1], "r");
	if (file != NULL)
	{
		if (!bQuiet)
			puts("...");

		uint8_t *code;
		uint8_t *data;

		// code/data 할당 및 초기화
		code = (uint8_t *)VirtualAlloc(nullptr, 64 * 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		data = (uint8_t *)VirtualAlloc(nullptr, 64 * 1024, MEM_COMMIT, PAGE_READWRITE);

		memset(data, 0, 64 * 1024);

		// JIT 컴파일 자료구조
		uint8_t *c = code;

		char kind;
		int counter = 0;

		ModifyInfo modify_info;
		modify_info.clear();
		modify_info.value = 0;
		modify_info.isLoadedOnEax = false;

		std::stack<uint8_t *> loop_labels;

		typedef std::pair<char, cmd_func_type> cmd_entry;
		std::vector<cmd_entry> cmd_func = {
			{ 'F', cmd_ForwardBack },
			{ '+', cmd_PlusMinus },
			{ 'I', cmd_Integer },
			{ 'C', cmd_Character },
			{ 'R', cmd_Real },
			{ 'S', cmd_Space },
			{ 'E', cmd_Enter },
			{ 'O', cmd_O_init },
			{ ':', cmd_label },
			{ ';', cmd_label_jmp },
			{ 'Q', cmd_Quit },
		};
		auto cmd_func_comp = [](const cmd_entry &lhs, const cmd_entry &rhs)
		{
			return lhs.first < rhs.first;
		};
		std::sort(cmd_func.begin(), cmd_func.end(), cmd_func_comp);

		// 스크립트 파싱 자료구조
		enum { FLAG_SUCS, FLAG_ERR };
		auto cmd_regular = [file](char ch, int &flag)
		{
			int counter = -1;
			if (ch == ',')
			{
				ch = '+';
				flag = read_int(file, &counter);
				if (flag != 1)
					flag = FLAG_ERR;
				else
					flag = FLAG_SUCS;
			}
			else if (ch == 'B')
				ch = 'F';
			else if (ch == '-')
				ch = '+';
			else
				counter = 1;
			return std::make_pair(ch, counter);
		};

		int ch;
		int flag, ret = 0;

		// 스크립트 파싱 & 컴파일
		while (1)
		{
			ch = my_fgetc(file);
			if (ch == EOF)
			{
				if (counter != -1)
				{
					// 최적화를 위해 미뤄졌던 컴파일을 수행
					auto it = std::lower_bound(
						cmd_func.begin(), cmd_func.end(),
						cmd_entry(kind, nullptr)
						);
					if (it != cmd_func.end())
						c = it->second(c, counter, loop_labels, modify_info);
				}
				break;
			}
			else if (isspace(ch))
			{
				// whitespace는 pass
				continue;
			}
			else if (ch == '#')
			{
				// 한줄 주석
				while (1)
				{
					ch = my_fgetc(file);
					if (ch == '\n' || ch == EOF)
						break;
				}

				if (ch == '\n')
					continue;
				else if (ch == EOF)
					break;
			}

			auto pr = cmd_regular(ch, flag);
			if (flag == FLAG_ERR)
			{
			error:
				fprintf(stderr, "syntax error\n");
				ret = -1;
				break;
			}

			if (counter == 0)
			{
			reset:
				kind = pr.first;
				counter = pr.second;
			}
			else if (kind == pr.first)
			{
				counter += pr.second;
			}
			else
			{
				auto it = std::lower_bound(
					cmd_func.begin(), cmd_func.end(),
					cmd_entry(kind, nullptr)
					);
				if (it != cmd_func.end())
				{
					c = it->second(c, counter, loop_labels, modify_info);
					goto reset;
				}
				else
				{
					goto error;
				}
			}
		}

		// 프로그램 끝에 ret 이 없으면 붙혀줌.
		if (*(c - 1) != 0xc3 /*ret*/)
			*(c - 1) = 0xc3;

		if (!bQuiet)
			puts("Compilation completed.\n");

		// (정상적으로 컴파일됬으면) 컴파일된 스크립트 실행 혹은 출력
		if (ret == 0)
		{
			if (output_file == nullptr)
			{
				// 코드 부분의 WRITE 권한을 없앰
				DWORD oldattr;
				VirtualProtect(code, 1024 * 1024, PAGE_EXECUTE_READ, &oldattr);

				__asm
				{
					pushad
					pushfd
					mov ebx, dword ptr [data]
					call code
					popfd
					popad
				}
			}
			else
			{
#ifdef _DEBUG
				output(code, c, output_file);
#else
				fprintf(stderr, "현재 컴파일 결과 출력 기능은 구현되지 않았습니다.\n");
#endif
			}
		}

		// code/data 할당 해제 및 종료
		VirtualFree(code, 64 * 1024, MEM_RELEASE);
		VirtualFree(data, 64 * 1024, MEM_RELEASE);

		return ret;
	}
	else
	{
		perror("fail to open the source file");
		return -1;
	}
}

uint8_t *ApplyModify(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi, bool bSaveToEax)
{
	int32_t initing_value = 0;

	if (mi.isModified)
	{
		if (mi.isRelative)
		{
			if (bSaveToEax)
			{
				*c++ = 0x8b; *c++ = 0x03;	// mov eax, [ebx]
				if (mi.value == 1)
				{
					*c++ = 0x40;			// inc eax
				}
				else if (mi.value == -1)
				{
					*c++ = 0x48;			// dec eax
				}
				else
				{
					*c++ = 0x05;			// add eax,
					*(int32_t *)c = mi.value;
					c += 4;
				}
				*c++ = 0x89; *c++ = 0x03;	// mov [ebx], eax
				mi.isLoadedOnEax = true;
			}
			else
			{
				*c++ = 0x81; *c++ = 0x03;	// add dword [ebx],
				*(int32_t *)c = mi.value;
				c += 4;
			}
		}
		else
		{
			if (bSaveToEax)
			{
				mi.isLoadedOnEax = false;
			}

			*c++ = 0xc7; *c++ = 0x03;		// mov dword [ebx],
			*(int32_t *)c = mi.value;
			c += 4;
		}
	}
	else if (bSaveToEax)
	{
		mi.isLoadedOnEax = false;
	}

	mi.clear();

	return c;
}

uint8_t *cmd_ForwardBack(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	c = ApplyModify(c, counter, loop_labels, mi, false);

	*c++ = 0x81; *c++ = 0xc3;	// add ebx,
	*(int32_t *)c = counter * 4;
	c += 4;
	return c;
}

uint8_t *cmd_PlusMinus(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	mi.go_modifying();
	mi.value += counter;
	return c;
}

uint8_t *cmd_Integer(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	c = ApplyModify(c, counter, loop_labels, mi, true);
	if (!mi.isLoadedOnEax)
	{
		*c++ = 0xff; *c++ = 0x33;			// push dword [ebx]
	}
	else
	{
		*c++ = 0x50;						// push eax
	}
	*c++ = 0x68;							// push
	*(const char **)c = "%d";
	c += 4;
	*c++ = 0xe8;							// call
	*(uint32_t *)c = get_displacement(c + 4, printf);
	c += 4;
	*c++ = 0x83; *c++ = 0xc4; *c++ = 0x08;	// add esp, 8
	return c;
}

uint8_t *cmd_Character(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	c = ApplyModify(c, counter, loop_labels, mi, true);
	if (!mi.isLoadedOnEax)
	{
		*c++ = 0xff; *c++ = 0x33;			// push dword [ebx]
	}
	else
	{
		*c++ = 0x50;						// push eax
	}
	*c++ = 0xe8;							// call
	*(uint32_t *)c = get_displacement(c + 4, putchar);
	c += 4;
	*c++ = 0x83; *c++ = 0xc4; *c++ = 0x04;	// add esp, 4
	return c;
}

uint8_t *cmd_Real(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	// 실수형이 아니기 때문에 정수형으로 대체
	return cmd_Integer(c, counter, loop_labels, mi);
}

uint8_t *cmd_Space(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	mi.isLoadedOnEax = false;
	*c++ = 0x6a; *c++ = ' ';				// push ' '
	*c++ = 0xe8;							// call
	*(uint32_t *)c = get_displacement(c + 4, putchar);
	c += 4;
	*c++ = 0x83; *c++ = 0xc4; *c++ = 0x04;	// add esp, 4
	return c;
}

uint8_t *cmd_Enter(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	mi.isLoadedOnEax = false;
	*c++ = 0x6a; *c++ = '\n';				// push '\n'
	*c++ = 0xe8;							// call
	*(uint32_t *)c = get_displacement(c + 4, putchar);
	c += 4;
	*c++ = 0x83; *c++ = 0xc4; *c++ = 0x04;	// add esp, 4
	return c;
}

uint8_t *cmd_O_init(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	mi.go_modifying();
	mi.isRelative = false;
	mi.value = 0;
	return c;
}

uint8_t *cmd_label(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	// 루프가 돌면 상황이 바뀔 수 있음.
	c = ApplyModify(c, counter, loop_labels, mi, false);
	mi.isLoadedOnEax = false;

	for (int i = 0; i < counter; i++)
		loop_labels.push(c);
	return c;
}

uint8_t *cmd_label_jmp(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	// 중첩(counter > 1)된 경우 어차피 한 개 있을 때와 효과가 같음.

	if (loop_labels.empty())
	{
		fprintf(stderr, "syntax error");
		exit(-1);
	}

	c = ApplyModify(c, counter, loop_labels, mi, true);
	if (!mi.isLoadedOnEax)
	{
		*c++ = 0x8b; *c++ = 0x03;	// mov eax, [ebx]
	}

	int32_t diff = loop_labels.top() - c;
	loop_labels.pop();

	*c++ = 0x09; *c++ = 0xc0;		// or eax, eax

	if (diff >= -128 /* 0x80 */)
	{
		*c++ = 0x75;				// jnz (short)
		*c++ = (uint8_t)(int8_t)(diff - 4); // short점프 2byte + or 2byte
	}
	else
	{
		*c++ = 0x0F; *c++ = 0x85;	// jnz (near)
		*(int32_t *)c = (diff - 8);  // near점프 6byte + or 2byte
		c += 4;
	}

	return c;
}

uint8_t *cmd_Quit(uint8_t *c, int counter, std::stack<uint8_t *> &loop_labels, ModifyInfo &mi)
{
	*c++ = 0xc3;	// ret
	return c;
}

int _fgetc_ungeted_char = -1;
int my_fgetc(FILE *file)
{
	if (_fgetc_ungeted_char == -1)
	{
		return fgetc(file);
	}
	else
	{
		char c = (char)_fgetc_ungeted_char;
		_fgetc_ungeted_char = -1;
		return c;
	}
}
void my_ungetc(char ch)
{
	assert(_fgetc_ungeted_char == -1);
	_fgetc_ungeted_char = ch;
}
int read_int(FILE *file, int *i)
{
	int ret = 0;
	int sign = 1;

	bool run_more_once = false;

	char ch = fgetc(file);
	if (ch == '+')
	{
		sign = 1;
	}
	else if (ch == '-')
	{
		sign = -1;
	}
	else if (isdigit(ch))
	{
		ret = ch - '0';
		run_more_once = true;
	}
	else
	{
		my_ungetc(ch);
		return -1;
	}

	while (isdigit(ch = fgetc(file)))
	{
		run_more_once = true;

		if (ret * 10 / 10 != ret)
			return -1;

		int old = ret * 10;
		ret = old + ch - '0';

		if (old > ret)
			return -1;
	}
	my_ungetc(ch);

	if (!run_more_once)
		return -1;

	*i = ret;
	return 1;
}
