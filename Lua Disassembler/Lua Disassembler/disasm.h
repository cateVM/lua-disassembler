/*****************************************************************************\
*                                                                             *
*						lua disassembler (core)								  *
*                        Author: CateVM | cate                                *
*						      (header)									      *
*                                                                             *
\*****************************************************************************/
#ifdef _WIN32
#pragma warning(disable:4996) // ; _CRT_SECURE_NO_WARNINGS
#endif
// Help:
//	Sample program:
//		#include <disasm.h>
//		std::vector<const char*> OpCodes;
//		std::vector <char*> OpCodeValues;
//		std::vector<char*> Constants;
//		int NumOfConstants = 0;
//		int NumOfOpCodes = 0;
//		std::ostringstream pseudoBytecode;
//		int main() {
//			lua_State* L = lua_open();
//			luaL_loadstring(L,"print'hello, world'");
//			TValue* top = L->top - 1; // get the object at the top of the lua stack
//			LClosure* func = (LClosure*)(top->value.gc);
//			Proto* p = func->p; // get proto from pointer
//			auto* disassembler = new disasm;
//			disassembler->GetConstants(L, Constants);
//			disassembler->parse(p, L, pseudoBytecode, NumOfOpCodes, NumOfConstants, OpCodeValues, OpCodes); // Constants,OpCodeValues,OpCodes should be filled with the app
//			delete disassembler;
//		}
//  Implementing into unix/linux:
//		most of the code *should* work for gcc/g++ (in disasm.h)
//		provided with the example above it should be pretty easy
//		to port this to unix/linux.
extern "C" {
#include "Lua/lapi.h"
#include "Lua/lauxlib.h"
#include "Lua/lualib.h"
#include "Lua/lua.h"
#include "Lua/lstate.h"
#include "Lua/lcode.h"
#include "Lua/lstring.h"
#include "Lua/ldo.h"
#include "Lua/lfunc.h"
#include "Lua/lmem.h"
#include "Lua/lobject.h"
#include "Lua/lopcodes.h"
#include "Lua/lstring.h"
}
#define LUA_OK 0
#ifdef __GNUC__ //Allow Lua disassembler to compile with gcc/g++ (tested on windows subsystem for ubuntu) __GNUC__ 
// [NOTE] The lua libs provided with this are for windows x86! so you'll probably have linking errors.
#include <cstring>
#define _strdup strdup
typedef unsigned char BYTE;
#endif // __GNUC__
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
struct disasm {
public:
	void GetConstants(lua_State* L, std::vector<char*> &Constants) {
		TValue* top = L->top - 1; // get the object/function at top of stack
		LClosure* func = (LClosure*)(top->value.gc); // interpret this object as an lua closure/function :heart:
		Proto* p = func->p; // get da proto
#ifdef DEBUG
		std::cout << "\n\n ---- CONSTANT LIST ----" << std::endl;
#endif
		for (int i = 0; i < p->sizek; i++) {
			TValue o = p->k[i];

			switch (o.tt) {
			case LUA_TNIL:
#ifdef DEBUG
				std::cout << "__NIL__" << std::endl;
#endif // DEBUG


				Constants.push_back(_strdup("NIL"));
				break;
			case LUA_TBOOLEAN:
				if (o.value.b == 0) {
#ifdef DEBUG
					std::cout << std::boolalpha << "__CONSTANT BOOL__ " << "FALSE" << std::endl;
#endif // DEBUG

					Constants.push_back(_strdup("BOOL : FALSE"));
				}
				else if (o.value.b == 1) {
#ifdef DEBUG
					std::cout << std::boolalpha << "__CONSTANT BOOL__ " << "TRUE" << std::endl;
#endif



					Constants.push_back(_strdup("BOOL : TRUE"));
				}

				break;
			case LUA_TNUMBER:
#ifdef DEBUG
				std::cout << "__CONSTANT INT__ " << o.value.n << std::endl;
#endif // DEBUG




				Constants.push_back(_strdup(std::to_string(o.value.n).c_str()));
				break;
			case LUA_TSTRING: {
#ifdef DEBUG
				std::cout << "__CONSTANT STRING__ " << getstr((TString*)o.value.gc) << std::endl;
#endif // DEBUG



				Constants.push_back(_strdup(getstr((TString*)o.value.gc)));
				break;
			}
				}
			}
		
	}
	void parse(Proto* p, lua_State* L,std::ostringstream &pseudoBytecode,int &NumOfOpCodes, int &NumOfConstants, std::vector<char*> &OpCodeValues, std::vector<const char*> &OpCodes) {
		
#ifdef DEBUG
		std::cout << " ---- BASIC INFO ----" << std::endl;
#endif 
#ifdef DEBUG
		std::cout << "__NUMBER OF OPCODES__ -> " << p->sizecode << std::endl;
#endif 

		NumOfOpCodes = p->sizecode;
#ifdef DEBUG
		std::cout << "__NUMBER OF CONSTANTS__ -> " << p->sizek << std::endl;
#endif 

		NumOfConstants = p->sizek;
#ifdef DEBUG
		printf("\n--- OPCODE LIST ---");
#endif 

		WriteOpCode(pseudoBytecode, 1); // compilation status 
		WriteOpCode(pseudoBytecode, p->sizek); // num of consts
		WriteOpCode(pseudoBytecode, p->sizep); // size of p
		WriteOpCode(pseudoBytecode, p->maxstacksize); // maxstacksize
		WriteOpCode(pseudoBytecode, p->numparams); // numparams
		WriteOpCode(pseudoBytecode, p->nups); // nups
		WriteOpCode(pseudoBytecode, p->is_vararg); // is_vararg
		for (int at = 0; at <= p->sizecode; at++) {
			Instruction i = p->code[at];
			switch (GET_OPCODE(p->code[at])) {

			case OP_LOADK: {
#ifdef DEBUG
				std::cout << "LOADK " << std::endl;
#endif // DEBUG


				OpCodes.push_back("OP_LOADK");
				switch (p->k[GETARG_Bx(i)].tt) {
				case LUA_TSTRING: // 4 = constant type string 
					OpCodeValues.push_back(_strdup(getstr((TString*)p->k[INDEXK(GETARG_Bx(i))].value.gc)));
					break;
				case LUA_TNUMBER:
					OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_Bx(i))].value.n).c_str()));
					break;
				}

				WriteOpCode(pseudoBytecode, OP_LOADK);
				break;
			}
			case OP_GETGLOBAL: {
				OpCodes.push_back("OP_GETGLOBAL");
				OpCodeValues.push_back(_strdup(getstr((TString*)p->k[INDEXK(GETARG_Bx(i))].value.gc))); // assuming its a string since getglbal only accepts strings (?)
				WriteOpCode(pseudoBytecode, OP_GETGLOBAL);
				break;
			}

			case OP_SETLIST:
#ifdef DEBUG
				printf("\nOP_SETLIST called");
#endif 

				OpCodes.push_back("OP_SETLIST");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_SETLIST);
				break;
			case OP_NEWTABLE:
#ifdef DEBUG
				printf("\nOP_NEWTABLE called");
#endif 

				OpCodes.push_back("OP_NEWTABLE");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_NEWTABLE);
				break;
			case OP_CALL:
#ifdef DEBUG
				printf("\nOP_CALL called");
#endif 

				OpCodes.push_back("OP_CALL");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_CALL);
				break;
			case OP_GETTABLE:
#ifdef DEBUG
				printf("\nOP_GETTABLE called");
#endif 
				OpCodes.push_back("OP_GETTABLE");
				switch (p->k[INDEXK(GETARG_C(i))].tt) {
				case LUA_TSTRING:
					OpCodeValues.push_back(_strdup(getstr((TString*)p->k[INDEXK(GETARG_C(i))].value.gc)));
					break;
				case LUA_TNUMBER:
					OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str()));
					break;
				}

				WriteOpCode(pseudoBytecode, OP_GETTABLE);
				break;
			case OP_RETURN:
#ifdef DEBUG
				printf("\nOP_RETURN called");
#endif 
				OpCodes.push_back("OP_RETURN");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_RETURN);
				break;
			case OP_SETGLOBAL:
				OpCodes.push_back("OP_SETGLOBAL");
				OpCodeValues.push_back(_strdup(getstr((TString*)p->k[INDEXK(GETARG_Bx(i))].value.gc))); // assuming its a string since setglobal only accepts strings (?)
				WriteOpCode(pseudoBytecode, OP_SETGLOBAL);
				break;
			case OP_ADD:
#ifdef DEBUG
				printf("\nOP_ADD called");
#endif 

				OpCodes.push_back("OP_ADD");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_ADD);
				break;
			case OP_SELF:
#ifdef DEBUG
				printf("\nOP_SELF called");
#endif 
				OpCodes.push_back("OP_SELF");
				OpCodeValues.push_back(_strdup(getstr((TString*)p->k[INDEXK(GETARG_C(i))].value.gc)));
				WriteOpCode(pseudoBytecode, OP_SELF);
				break;
			case OP_CLOSURE: {

#ifdef DEBUG
				printf("\nOP_CLOSURE (function) called");
				printf("\n[ENTERING NEW FUNCTION/CLOSURE]");
#endif 
				OpCodes.push_back(strcat(_strdup("OP_CLOSURE "),std::to_string(GETARG_Bx(i)).c_str()));
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_CLOSURE);
#ifdef DISASM_NO_PARSE_FUNCTION

#else
				
				parse_function(p->p[GETARG_Bx(i)], pseudoBytecode, NumOfOpCodes, NumOfConstants, OpCodeValues, OpCodes);
#endif // DISASM_NO_PARSE_FUNCTION

				
#ifdef DEBUG
				printf("\n[END OF FUNCTION/CLOSURE]");
#endif 


				break;
			}

			case OP_SUB:
#ifdef DEBUG
				printf("\nOP_SUB called");
#endif 

				OpCodes.push_back("OP_SUB");
				OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str())); // assuming double/int type
				WriteOpCode(pseudoBytecode, OP_SUB);
				break;
			case OP_POW:
				OpCodes.push_back("OP_POW");
				OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str())); // assuming double/int type
				WriteOpCode(pseudoBytecode, OP_POW);
				break;
			case OP_EQ:
#ifdef DEBUG
				printf("\nOP_EQ called");
#endif 
				OpCodes.push_back("OP_EQ");
				{

					char* val;
					// RK(x) == if ISK(x) then Kst(INDEXK(x)) else R(x)
					if (ISK(GETARG_C(i))) {
						switch (p->k[INDEXK(GETARG_C(i))].tt) {
						case LUA_TNUMBER:
							val = _strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str());
							break;
						case LUA_TSTRING:
							val = _strdup(getstr((TString*)p->k[INDEXK(GETARG_C(i))].value.gc));
							break;
						default: // hmmm it isnt a string or int lets just set it to ??? so msvc doesnt error
							val = _strdup("???");
							break;
						}

					}
					else { // not a const
						val = _strdup(std::to_string(GETARG_C(i)).c_str());
					}

					OpCodeValues.push_back(_strdup(val));
					WriteOpCode(pseudoBytecode, OP_EQ);
				}
				break;
			case OP_DIV:
#ifdef DEBUG
				printf("\nOP_DIV called");
#endif 
				OpCodes.push_back("OP_DIV");
				OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str())); // assuming double/int type
				WriteOpCode(pseudoBytecode, OP_DIV);
				break;
			case OP_MUL:
#ifdef DEBUG
				printf("\nOP_MUL called");
#endif 

				OpCodes.push_back("OP_MUL");
				OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str())); // assuming double/int type
				WriteOpCode(pseudoBytecode, OP_MUL);
				break;
			case OP_SETUPVAL:
#ifdef DEBUG
				printf("\nOP_SETUPVAL called");
#endif 

				OpCodes.push_back("OP_SETUPVAL");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_SETUPVAL);
				break;
			case OP_FORLOOP:
#ifdef DEBUG
				printf("\nOP_FORLOOP called");
#endif 
				OpCodes.push_back("OP_FORLOOP");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_FORLOOP);
				break;
			case OP_FORPREP:
#ifdef DEBUG
				printf("\nOP_FORPREP called");
#endif 
				OpCodes.push_back("OP_FORPREP");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_FORPREP);
				break;
			case OP_CLOSE:

#ifdef DEBUG
				printf("\nOP_CLOSE called");
#endif 
				OpCodes.push_back("OP_CLOSE");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_CLOSE);
				break;
			case OP_CONCAT:
#ifdef DEBUG
				printf("\nOP_CONCAT called");
#endif 
				OpCodes.push_back("OP_CONCAT");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_CONCAT);
				break;
			case OP_LOADBOOL:
#ifdef DEBUG
				printf("\nOP_LOADBOOL called");
				std::cout << "LOADBOOL Value : " << GETARG_B(i);
#endif 
				//std::cout << GETARG_B(i) << std::endl;
				OpCodes.push_back("OP_LOADBOOL");
				OpCodeValues.push_back(GETARG_B(i) ? _strdup("true") : _strdup("false"));
				WriteOpCode(pseudoBytecode, OP_LOADBOOL);
				break;
			case OP_MOVE:
#ifdef DEBUG
				printf("\nOP_MOVE called");
#endif 

				OpCodes.push_back("OP_MOVE");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_MOVE);
				break;
			case OP_VARARG:
#ifdef DEBUG
				printf("\nOP_VARARG (...) called");
#endif 

				OpCodes.push_back("OP_VARARG");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_VARARG);
				break;
			case OP_TEST:
				OpCodes.push_back("OP_TEST");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_TEST);
				break;
			case OP_JMP:
#ifdef DEBUG
				std::cout << "sBX = " << GETARG_sBx(i) << std::endl;
#endif // DEBUG

				

				OpCodes.push_back("OP_JMP");
				OpCodeValues.push_back(strcat(_strdup("JMP TO [+"), strcat(_strdup(std::to_string(GETARG_sBx(i)).c_str()), "]")));
				WriteOpCode(pseudoBytecode, OP_JMP);
				break;
			case OP_LOADNIL:
				OpCodes.push_back("OP_LOADNIL");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_LOADNIL);
				break;
			case OP_TFORLOOP: {
				OpCodes.push_back("OP_TFORLOOP");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_TFORLOOP);
				break;
			}
			case OP_LEN:
				OpCodes.push_back("OP_LEN");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_LEN);
				break;
			case OP_SETTABLE:
				OpCodes.push_back("OP_SETTABLE");
				char* val;
				char* what;
				// RK(x) == if ISK(x) then Kst(INDEXK(x)) else R(x)
				if (ISK(GETARG_C(i))) {

					if (p->k[INDEXK(GETARG_C(i))].tt == LUA_TSTRING) {
						val = _strdup(getstr((TString*)p->k[INDEXK(GETARG_C(i))].value.gc));
					}
					else {
						val = _strdup("unable to get const");
					}

				}
				else {
					val = _strdup(std::to_string(GETARG_C(i)).c_str());
				}
				if (ISK(GETARG_B(i))) {
					what = _strdup(std::to_string(p->k[INDEXK(GETARG_B(i))].value.n).c_str());
				}
				else {
					what = _strdup(std::to_string(GETARG_B(i)).c_str());
				}



				OpCodeValues.push_back(strcat(strcat(what, " "), val));
#ifdef DEBUG
				std::cout << "\n OP_SETTABLE ;" << val << " " << what;
#endif // DEBUG
				WriteOpCode(pseudoBytecode, OP_SETTABLE);
				break;
#ifdef __GNUC__
			default:
				break;
#endif // __GNUC__


			}

		}
		


	}
	void parse_function(Proto* p, std::ostringstream& pseudoBytecode, int& NumOfOpCodes, int& NumOfConstants, std::vector<char*>& OpCodeValues, std::vector<const char*>& OpCodes) {
		int tmp_ = p->sizecode; // opcodes
		int tmp = p->sizek; // consts
#ifdef DEBUG
		printf("\n__ FUNCTION CONSTS __ -> %d", p->sizek);
		printf("\n__ FUNCTION OPCODES __ -> %d", p->sizecode);
#endif // DEBUG


		NumOfConstants = NumOfConstants + tmp;
		NumOfOpCodes = NumOfOpCodes + tmp_;
		
		for (int at = 0; at <= p->sizecode; at++) {
			Instruction i = p->code[at];

			switch (GET_OPCODE(p->code[at])) {

			case OP_LOADK: {
#ifdef DEBUG
				std::cout << "LOADK " << std::endl;
#endif // DEBUG


				OpCodes.push_back("\tOP_LOADK");
				switch (p->k[GETARG_Bx(i)].tt) {
				case LUA_TSTRING: // 4 = constant type string 
					OpCodeValues.push_back(_strdup(getstr((TString*)p->k[INDEXK(GETARG_Bx(i))].value.gc)));
					break;
				case LUA_TNUMBER:
					OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_Bx(i))].value.n).c_str()));
					break;
				}

				WriteOpCode(pseudoBytecode, OP_LOADK);
				break;
			}
			case OP_GETGLOBAL: {
				OpCodes.push_back("\tOP_GETGLOBAL");
				OpCodeValues.push_back(_strdup(getstr((TString*)p->k[INDEXK(GETARG_Bx(i))].value.gc))); // assuming its a string since getglbal only accepts strings (?)
				WriteOpCode(pseudoBytecode, OP_GETGLOBAL);
				break;
			}

			case OP_SETLIST:
#ifdef DEBUG
				printf("\nOP_SETLIST called");
#endif 

				OpCodes.push_back("\tOP_SETLIST");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_SETLIST);
				break;
			case OP_NEWTABLE:
#ifdef DEBUG
				printf("\nOP_NEWTABLE called");
#endif 

				OpCodes.push_back("\tOP_NEWTABLE");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_NEWTABLE);
				break;
			case OP_CALL:
#ifdef DEBUG
				printf("\nOP_CALL called");
#endif 

				OpCodes.push_back("\tOP_CALL");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_CALL);
				break;
			case OP_GETTABLE:
#ifdef DEBUG
				printf("\nOP_GETTABLE called");
#endif 
				OpCodes.push_back("\tOP_GETTABLE");
				switch (p->k[INDEXK(GETARG_C(i))].tt) {
				case LUA_TSTRING:
					OpCodeValues.push_back(_strdup(getstr((TString*)p->k[INDEXK(GETARG_C(i))].value.gc)));
					break;
				case LUA_TNUMBER:
					OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str()));
					break;
				}

				WriteOpCode(pseudoBytecode, OP_GETTABLE);
				break;
			case OP_RETURN:
#ifdef DEBUG
				printf("\nOP_RETURN called");
#endif 
				OpCodes.push_back("\tOP_RETURN");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_RETURN);
				break;
			case OP_SETGLOBAL:
				OpCodes.push_back("\tOP_SETGLOBAL");
				OpCodeValues.push_back(_strdup(getstr((TString*)p->k[INDEXK(GETARG_Bx(i))].value.gc))); // assuming its a string since setglobal only accepts strings (?)
				WriteOpCode(pseudoBytecode, OP_SETGLOBAL);
				break;
			case OP_ADD:
#ifdef DEBUG
				printf("\nOP_ADD called");
#endif 

				OpCodes.push_back("\tOP_ADD");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_ADD);
				break;
			case OP_SELF:
#ifdef DEBUG
				printf("\nOP_SELF called");
#endif 
				OpCodes.push_back("\tOP_SELF");
				OpCodeValues.push_back(_strdup(getstr((TString*)p->k[INDEXK(GETARG_C(i))].value.gc)));
				WriteOpCode(pseudoBytecode, OP_SELF);
				break;
			case OP_CLOSURE: {

#ifdef DEBUG
				printf("\nOP_CLOSURE (function) called");
				printf("\n[ENTERING NEW FUNCTION/CLOSURE]");
#endif 

				OpCodes.push_back(strcat(_strdup("OP_CLOSURE "), std::to_string(GETARG_Bx(i)).c_str()));
				
				WriteOpCode(pseudoBytecode, OP_CLOSURE);
#ifdef DISASM_NO_FUNCTION_RECURSION

#else
				parse_function(p->p[GETARG_Bx(i)],pseudoBytecode,NumOfOpCodes,NumOfConstants,OpCodeValues,OpCodes);
#endif
#ifdef DEBUG
				printf("\n[END OF FUNCTION/CLOSURE]");
#endif 


				break;
			}

			case OP_SUB:
#ifdef DEBUG
				printf("\nOP_SUB called");
#endif 

				OpCodes.push_back("\tOP_SUB");
				OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str())); // assuming double/int type
				WriteOpCode(pseudoBytecode, OP_SUB);
				break;
			case OP_POW:
				OpCodes.push_back("\tOP_POW");
				OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str())); // assuming double/int type
				WriteOpCode(pseudoBytecode, OP_POW);
				break;
			case OP_EQ:
#ifdef DEBUG
				printf("\nOP_EQ called");
#endif 
				OpCodes.push_back("\tOP_EQ");
				{

					char* val;
					// RK(x) == if ISK(x) then Kst(INDEXK(x)) else R(x)
					if (ISK(GETARG_C(i))) {
						switch (p->k[INDEXK(GETARG_C(i))].tt) {
						case LUA_TNUMBER:
							val = _strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str());
							break;
						case LUA_TSTRING:
							val = _strdup(getstr((TString*)p->k[INDEXK(GETARG_C(i))].value.gc));
							break;
						default: // hmmm it isnt a string or int lets just set it to ??? so msvc doesnt error
							val = _strdup("???");
							break;
						}

					}
					else { // not a const
						val = _strdup(std::to_string(GETARG_C(i)).c_str());
					}

					OpCodeValues.push_back(_strdup(val));
					WriteOpCode(pseudoBytecode, OP_EQ);
				}
				break;
			case OP_DIV:
#ifdef DEBUG
				printf("\nOP_DIV called");
#endif 
				OpCodes.push_back("\tOP_DIV");
				OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str())); // assuming double/int type
				WriteOpCode(pseudoBytecode, OP_DIV);
				break;
			case OP_MUL:
#ifdef DEBUG
				printf("\nOP_MUL called");
#endif 

				OpCodes.push_back("\tOP_MUL");
				OpCodeValues.push_back(_strdup(std::to_string(p->k[INDEXK(GETARG_C(i))].value.n).c_str())); // assuming double/int type
				WriteOpCode(pseudoBytecode, OP_MUL);
				break;
			case OP_SETUPVAL:
#ifdef DEBUG
				printf("\nOP_SETUPVAL called");
#endif 

				OpCodes.push_back("\tOP_SETUPVAL");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_SETUPVAL);
				break;
			case OP_FORLOOP:
#ifdef DEBUG
				printf("\nOP_FORLOOP called");
#endif 
				OpCodes.push_back("\tOP_FORLOOP");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_FORLOOP);
				break;
			case OP_FORPREP:
#ifdef DEBUG
				printf("\nOP_FORPREP called");
#endif 
				OpCodes.push_back("\tOP_FORPREP");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_FORPREP);
				break;
			case OP_CLOSE:

#ifdef DEBUG
				printf("\nOP_CLOSE called");
#endif 
				OpCodes.push_back("\tOP_CLOSE");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_CLOSE);
				break;
			case OP_CONCAT:
#ifdef DEBUG
				printf("\nOP_CONCAT called");
#endif 
				OpCodes.push_back("\tOP_CONCAT");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_CONCAT);
				break;
			case OP_LOADBOOL:
#ifdef DEBUG
				printf("\nOP_LOADBOOL called");
				std::cout << "LOADBOOL Value : " << GETARG_B(i);
#endif 

				OpCodes.push_back("\tOP_LOADBOOL");
				OpCodeValues.push_back(GETARG_B(i) ? _strdup("true") : _strdup("false"));
				WriteOpCode(pseudoBytecode, OP_LOADBOOL);
				break;
			case OP_MOVE:
#ifdef DEBUG
				printf("\nOP_MOVE called");
#endif 

				OpCodes.push_back("\tOP_MOVE");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_MOVE);
				break;
			case OP_VARARG:
#ifdef DEBUG
				printf("\nOP_VARARG (...) called");
#endif 

				OpCodes.push_back("\tOP_VARARG");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_VARARG);
				break;
			case OP_TEST:
				OpCodes.push_back("\tOP_TEST");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_TEST);
				break;
			case OP_JMP:
#ifdef DEBUG
				std::cout << "sBX = " << GETARG_sBx(i) << std::endl;
#endif // DEBUG

				

				OpCodes.push_back("\tOP_JMP");
				OpCodeValues.push_back(strcat(_strdup("JMP TO[+"), strcat(_strdup(std::to_string(GETARG_sBx(i)).c_str()), "]")));
				WriteOpCode(pseudoBytecode, OP_JMP);
				break;
			case OP_LOADNIL:
				OpCodes.push_back("\tOP_LOADNIL");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_LOADNIL);
				break;
			case OP_TFORLOOP: {
				OpCodes.push_back("\tOP_TFORLOOP");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_TFORLOOP);
				break;
			}
			case OP_LEN:
				OpCodes.push_back("\tOP_LEN");
				OpCodeValues.push_back(_strdup("---"));
				WriteOpCode(pseudoBytecode, OP_LEN);
				break;
			case OP_SETTABLE:
				OpCodes.push_back("\tOP_SETTABLE");
				char* val;
				char* what;
				// RK(x) == if ISK(x) then Kst(INDEXK(x)) else R(x)
				if (ISK(GETARG_C(i))) {
					if (p->k[INDEXK(GETARG_C(i))].tt == LUA_TSTRING) {
						val = _strdup(getstr((TString*)p->k[INDEXK(GETARG_C(i))].value.gc));
					}
					else {
						val = _strdup("nig");
					}

				}
				else {
					val = _strdup(std::to_string(GETARG_C(i)).c_str());
				}
				if (ISK(GETARG_B(i))) {
					what = _strdup(std::to_string(p->k[INDEXK(GETARG_B(i))].value.n).c_str());
				}
				else {
					what = _strdup(std::to_string(GETARG_B(i)).c_str());
				}



				OpCodeValues.push_back(strcat(strcat(what, " "), val));
#ifdef DEBUG
				std::cout << "\n OP_SETTABLE ;" << val << " " << what;
#endif // DEBUG
				WriteOpCode(pseudoBytecode, OP_SETTABLE);
				break;
#ifdef __GNUC__
			default:
				break;
#endif // __GNUC__



			}

		}
		OpCodes.push_back(".end closure");
		OpCodeValues.push_back(_strdup("---"));
	}
	private:
		static void WriteOpCode(std::ostringstream& ss, BYTE value) {
			ss.write(reinterpret_cast<const char*>(&value), sizeof(value));
		}


};
