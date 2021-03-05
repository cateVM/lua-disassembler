/*****************************************************************************\
*                                                                             *
*							lua disassembler								  *
*                         Author: CateVM | cate                               *
*							  (ui code)										  *
*                                                                             *
\*****************************************************************************/
#ifdef _WIN32
#pragma warning(disable:4996) // ; _CRT_SECURE_NO_WARNINGS
#endif
/*
* A lua disassembler for Lua 5.1
* !!! has not been tested with x64 !!!
* 
* [KNOWN BUGS]
* if your lua file has escape sequences in it 
* the constant list might be broken e.g \132\420\69
* 
* unreasonably large files *will* mostly crash lua disassembler
* 
*/
#ifdef _WIN32
#else
#error "only MSVC is supported for this, see disasm.h for implementing this for linux/unix"
#endif


/*
* Uncomment the line below if you want debug info.
*/
// #define DEBUG
/*uncomment the line below if you do not want to parse functions inside functions
* e.g
* function func1(...)
*	function func2(...) <-- this function wont get parsed and will get ignored
*		print(...)
*	end
* end
*/
//#define DISASM_NO_FUNCTION_RECURSION

/*uncomment the line below if you would not like to parse any functions*/
// #define DISASM_NO_PARSE_FUNCTION



//ImGui Includes
// [NOTE] this uses a modified version of ImGui_ImplDX11_CreateWindow located in imgui_impl_dx11.cpp
// if you update imgui-docking in the foreseeable future please make the according changes.
#include "imgui-docking/imgui.h"
#include "imgui-docking/backends/imgui_impl_win32.h"
#include "imgui-docking/backends/imgui_impl_dx11.h"
#include "imgui_memory_editor.h"
#include "imgui_markdown.h"
#include <d3d11.h>
#pragma comment(lib, "d3d11.lib")
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>
#include <tchar.h>

// tinyfiledialogs 
#include "tinyfiledialogs.h"

#include "disasm.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <comdef.h>
#include "Shellapi.h"
#include <string>
static ImGui::MarkdownConfig mdConfig;

#define exec_file(l,f) luaL_dofile(l,f);
#define load_file(l,f) luaL_loadfile(l,f);
static void dumpstack(lua_State* L) {
	printf("---- DUMP STACK ----\n");
	int top = lua_gettop(L);
	for (int i = 1; i <= top; i++) {
		printf("%d\t%s\t", i, luaL_typename(L, i));
		switch (lua_type(L, i)) {
		case LUA_TNUMBER:
			printf("%g\n", lua_tonumber(L, i));
			break;
		case LUA_TSTRING:
			printf("%s\n", lua_tostring(L, i));
			break;
		case LUA_TBOOLEAN:
			printf("%s\n", (lua_toboolean(L, i) ? "true" : "false"));
			break;
		case LUA_TNIL:
			printf("%s\n", "nil");
			break;
		default:
			printf("%p\n", lua_topointer(L, i));
			break;
		}
	}
	printf("---- DUMP STACK ----\n");
}
// test
std::string removeEscapeSequences(const std::string& x)
{
	std::string buf;
	buf.reserve(x.size());
	for (const char c : x) {
		switch (c) 
		{
		case '\a':  buf += "\\a";        break;
		case '\b':  buf += "\\b";        break;
		case '\f':  buf += "\\f";        break;
		case '\n':  buf += "\\n";        break;
		case '\r':  buf += "\\r";        break;
		case '\t':  buf += "\\t";        break;
		case '\v':  buf += "\\v";        break;
		}
	}

	return buf;
}
static void HelpMarker(const char* desc)
{
	ImGui::TextDisabled("(?)");
	if (ImGui::IsItemHovered())
	{
		ImGui::BeginTooltip();
		ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
		ImGui::TextUnformatted(desc);
		ImGui::PopTextWrapPos();
		ImGui::EndTooltip();
	}
}
void LinkCallback(ImGui::MarkdownLinkCallbackData data_);

void LinkCallback(ImGui::MarkdownLinkCallbackData data_)
{
	std::string url(data_.link, data_.linkLength);
	if (!data_.isImage)
	{
		ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
	}
}
void MarkdownFormatCallback(const ImGui::MarkdownFormatInfo& markdownFormatInfo_, bool start_)
{
	// Call the default first so any settings can be overwritten by our implementation.
	// Alternatively could be called or not called in a switch statement on a case by case basis.
	// See defaultMarkdownFormatCallback definition for further examples of how to use it.
	ImGui::defaultMarkdownFormatCallback(markdownFormatInfo_, start_);

	switch (markdownFormatInfo_.type)
	{
		
	case ImGui::MarkdownFormatType::HEADING:
	{
		if (markdownFormatInfo_.level == 2)
		{
			if (start_)
			{
				ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyle().Colors[ImGuiCol_TextDisabled]);
			}
			else
			{
				ImGui::PopStyleColor();
			}
		}
		break;
	}
	default:
	{
		break;
	}
	}
}
void Markdown(const std::string& markdown_)
{
	mdConfig.linkCallback = LinkCallback;
	mdConfig.tooltipCallback = NULL;
	mdConfig.userData = NULL;
	mdConfig.formatCallback = MarkdownFormatCallback;
	ImGui::Markdown(markdown_.c_str(), markdown_.length(), mdConfig);
}

typedef struct LoadS {
	const char* s;
	size_t size;
} LoadS;
static const char* getS(lua_State* L, void* ud, size_t* size) {
	LoadS* ls = (LoadS*)ud;
	(void)L;
	if (ls->size == 0) return NULL;
	*size = ls->size;
	ls->size = 0;
	return ls->s;
}
// Important variables
static char data[0x10000];
size_t data_size = 0x10000;
std::vector<const char*> OpCodes;
std::vector <char*> OpCodeValues;
std::vector<char*> Constants;
int NumOfConstants = 0;
int NumOfOpCodes = 0;
std::ostringstream pseudoBytecode;




// Data
static ID3D11Device* g_pd3dDevice = NULL;
static ID3D11DeviceContext* g_pd3dDeviceContext = NULL;
static IDXGISwapChain* g_pSwapChain = NULL;
static ID3D11RenderTargetView* g_mainRenderTargetView = NULL;

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
// Main code
char* OpenedFile;
bool error = false;
bool about = false;
char message[99999];

int main(int argc, char* argv[])
{
	printf("\n ### Lua disassembler ### \n");
	// Create application window
	//ImGui_ImplWin32_EnableDpiAwareness();
	WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, _T("disassembler"), NULL };
	::RegisterClassEx(&wc);
	HWND hwnd = ::CreateWindow(wc.lpszClassName, _T("disassembler"), WS_OVERLAPPEDWINDOW, 100, 100, 0, 0, NULL, NULL, wc.hInstance, NULL);

	// Initialize Direct3D
	if (!CreateDeviceD3D(hwnd))
	{
		CleanupDeviceD3D();
		::UnregisterClass(wc.lpszClassName, wc.hInstance);
		return 1;
	}
	DragAcceptFiles(hwnd, 0x1);
	// Show the window

	::UpdateWindow(hwnd);

	// Setup Dear ImGui context
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO(); (void)io;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;       // Enable Keyboard Controls
	//io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
	io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;         // Enable Multi-Viewport / Platform Windows
	//io.ConfigViewportsNoAutoMerge = true;
	//io.ConfigViewportsNoTaskBarIcon = true;
	//io.ConfigViewportsNoDefaultParent = true;
	//io.ConfigDockingAlwaysTabBar = true;
	//io.ConfigDockingTransparentPayload = true;
	// Setup Dear ImGui style
	ImGui::StyleColorsDark();
	//ImGui::StyleColorsClassic();

	
	ImGuiStyle& style = ImGui::GetStyle();
	if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
	{
		style.WindowRounding = 0.0f;
		style.Colors[ImGuiCol_WindowBg].w = 1.0f;
	}

	// Setup Platform/Renderer backends
	ImGui_ImplWin32_Init(hwnd);
	ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

	// Load Fonts
	// - If no fonts are loaded, dear imgui will use the default font. You can also load multiple fonts and use ImGui::PushFont()/PopFont() to select them.
	// - AddFontFromFileTTF() will return the ImFont* so you can store it if you need to select the font among multiple.
	// - If the file cannot be loaded, the function will return NULL. Please handle those errors in your application (e.g. use an assertion, or display an error and quit).
	// - The fonts will be rasterized at a given size (w/ oversampling) and stored into a texture when calling ImFontAtlas::Build()/GetTexDataAsXXXX(), which ImGui_ImplXXXX_NewFrame below will call.
	// - Read 'docs/FONTS.md' for more instructions and details.
	// - Remember that in C/C++ if you want to include a backslash \ in a string literal you need to write a double backslash \\ !
	//io.Fonts->AddFontDefault();
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/Roboto-Medium.ttf", 16.0f);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/Cousine-Regular.ttf", 15.0f);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/DroidSans.ttf", 16.0f);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/ProggyTiny.ttf", 10.0f);
	//ImFont* font = io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\ArialUni.ttf", 18.0f, NULL, io.Fonts->GetGlyphRangesJapanese());
	//IM_ASSERT(font != NULL);

	ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

	// Main loop
	MSG msg;
	ZeroMemory(&msg, sizeof(msg));
	static MemoryEditor mem_edit_2;
	
	char const* lFilterPatterns[2] = { "*.lua","*.txt" }; // file filters
	static bool needsClose = true;
	while (msg.message != WM_QUIT)
	{
		
		if (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
		{
			::TranslateMessage(&msg);
			::DispatchMessage(&msg);
			continue;
		}

		// Start the Dear ImGui frame
		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();
		

		{


			ImGui::Begin("Lua disassembler", &needsClose, ImGuiWindowFlags_MenuBar);
			if (!needsClose) {
				ImGui::OpenPopup("Lua disassembler##Quit");
				needsClose = true;
			}
			if (ImGui::BeginMenuBar())
			{
				if (ImGui::BeginMenu("File"))
				{
					if (ImGui::MenuItem("Open file for disassembling"))
					{
						/*
						* Clearing all the vectors...
						* and our pseudoBytecode list...
						*/
					
					OPEN_DIALOG:

						char const* FileDialog = tinyfd_openFileDialog(
							"Select a lua file to disassemble",
							0,
							2,
							lFilterPatterns,
							NULL,
							0 // forbid multiple selections
						);

						if (FileDialog != NULL) {
						CLEAR:
							OpCodes.clear(); // clear our opcode list
							OpCodeValues.clear(); // clear our opcode value list
							Constants.clear(); // clear our Constants list
							pseudoBytecode.str(""); // clear our pseudo pseudo Bytecode list
							memset(&message[0], 0, sizeof(message)); // clear our pseudo Bytecode char array
							lua_State* L = lua_open();

							luaL_openlibs(L);
							std::string script;
							std::ifstream ifs(FileDialog);
							script.assign((std::istreambuf_iterator<char>(ifs)),
								(std::istreambuf_iterator<char>()));
							LoadS ls;
							ls.s = script.c_str();
							ls.size = strlen(script.c_str());
							if (lua_load(L, getS, &ls, "@Lua_Disassembler") != LUA_OK) { // lua file errored
							ERROR_:
#ifdef DEBUG
								printf("Unable to load file details: \n%s", lua_tostring(L, -1));
#endif // DEBUG
								error = true;


							}
							else { // LUA_OK
								OpenedFile = _strdup(FileDialog);
								{
								PARSE:
									TValue* top = L->top - 1; // get the object at the top of the lua stack
									LClosure* func = (LClosure*)(top->value.gc); // interpret this object as an LClosure*
									Proto* p = func->p; // get proto from pointer

									
									auto* disassembler = new disasm;
									disassembler->GetConstants(L, Constants);
									disassembler->parse(p, L, pseudoBytecode, NumOfOpCodes, NumOfConstants, OpCodeValues, OpCodes);
									delete disassembler;
#ifdef DEBUG
									std::cout << "\n ---- OUTPUT OF FILE ----" << std::endl;
#endif // DEBUG


									
#ifdef DEBUG
									lua_pcall(L, 0, 0, 0);
									dumpstack(L);
#endif // DEBUG


									lua_close(L);
#ifdef DEBUG
									printf("\nsize of opcode vector -> %d", OpCodes.size());
#endif // DEBUG
								}


							}
							std::string pseudoBytecode_s = pseudoBytecode.str();

							message[0] = '\0';

							for (int i = 0; i < pseudoBytecode_s.length(); i++) {
								char c[6];
								sprintf(c, "%02X ", (BYTE)pseudoBytecode_s[i]);
								strcat(message, c);
								if (i + 1 % 12 == 0) {
									strcat(message, "\n");
								}
							}
#ifdef DEBUG
							std::cout << message << std::endl;
#endif // DEBUG
						}

					}


					if (ImGui::MenuItem("Close file"))
					{
						OpCodes.clear(); // clear our opcode list
						OpCodeValues.clear(); // clear our opcode value list
						Constants.clear(); // clear our Constants list
						pseudoBytecode.str(""); // clear our pseudo pseudoBytecode list
						memset(&message[0], 0, sizeof(message)); // clear our pseudoBytecode char array
						NumOfConstants = 0;
						NumOfOpCodes = 0;

					}
					if (ImGui::MenuItem("Re-Analyze")) {
						if (!OpenedFile) {
							printf("no file currently opened");
						}
						else {
							OpCodes.clear(); // clear our opcode list
							OpCodeValues.clear(); // clear our opcode value list
							Constants.clear(); // clear our Constants list
							pseudoBytecode.str(""); // clear our pseudo Bytecode list
							memset(&message[0], 0, sizeof(message)); // clear our pseudo Bytecode char array
							NumOfConstants = 0;
							NumOfOpCodes = 0;
							std::string script;
							std::ifstream ifs(OpenedFile);
							script.assign((std::istreambuf_iterator<char>(ifs)),
								(std::istreambuf_iterator<char>()));
							lua_State* L = lua_open();

							luaL_openlibs(L);
							LoadS ls;
							ls.s = script.c_str();
							ls.size = strlen(script.c_str());

							if (lua_load(L, getS, &ls, "@Lua_Disassembler") != LUA_OK) { // lua file errored
							ERROR__:
#ifdef DEBUG
								printf("Unable to load file details: \n%s", lua_tostring(L, -1));
#endif // DEBUG
								error = true;


							}
							else { // LUA_OK
								{
								PARSE_:
									TValue* top = L->top - 1; // get da object at the top of the stack
									LClosure* func = (LClosure*)(top->value.gc);
									Proto* p = func->p;

									
									auto* disassembler = new disasm;
									disassembler->GetConstants(L, Constants);
									disassembler->parse(p, L, pseudoBytecode, NumOfOpCodes, NumOfConstants, OpCodeValues, OpCodes);
									delete disassembler;
#ifdef DEBUG
									std::cout << "\n ---- OUTPUT OF FILE ----" << std::endl;
#endif // DEBUG


									
#ifdef DEBUG
									lua_pcall(L, 0, 0, 0);
									dumpstack(L);
#endif // DEBUG


									lua_close(L);
#ifdef DEBUG
									printf("\nsize of opcode vector -> %d", OpCodes.size());
#endif
								}


							}
							std::string pseudoBytecode_s = pseudoBytecode.str();

							message[0] = '\0';

							for (int i = 0; i < pseudoBytecode_s.length(); i++) {
								char temp[6];
								sprintf(temp, "%02X ", (BYTE)pseudoBytecode_s[i]);
								strcat(message, temp);
								if (i + 1 % 12 == 0) 
								{
									strcat(message, "\n");
								}
							}
#ifdef DEBUG
							std::cout << message << std::endl;
#endif

						}



					}


					ImGui::EndMenu();
				}
				if (ImGui::BeginMenu("About Lua disassembler")) {
					if (ImGui::MenuItem("About")) {
						about = true;
					}


					ImGui::EndMenu();
				}

				ImGui::EndMenuBar();
			}
			if (error)
			{
				ImGui::OpenPopup("Unable to load file due to syntax error");
			}
			if (about) {
				ImGui::OpenPopup("About lua disassembler");
			}
			if (ImGui::BeginPopupModal("Unable to load file due to syntax error")) {
				ImGui::Text("Please check the file for syntax error's!");
				if (ImGui::Button("Close")) {
					ImGui::CloseCurrentPopup();
					error = false;
				}
				ImGui::EndPopup();
			}
			ImGui::SetNextWindowSize(ImVec2(353, 75));
			if (ImGui::BeginPopupModal("Lua disassembler##Quit")) {
				ImGui::Text("Are you sure you want to close lua disassembler?");
				if (ImGui::Button("Yes")) {
					ImGui::CloseCurrentPopup();
					exit(0);
				}
				ImGui::SameLine();
				if (ImGui::Button("No")) {
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}
			ImGui::SetNextWindowSize(ImVec2(525, 184));
			if (ImGui::BeginPopupModal("About lua disassembler")) {
#ifdef DEBUG
				const std::string markdownText = u8R"(# Lua disassembler
	* [Dear ImGui](https://github.com/ocornut/imgui) a bloat-free graphical user interface library for C++
	* [ImGui markdown](https://github.com/juliettef/imgui_markdown) Markdown for Dear ImGui
	* Disassembler Made by [cateVM](https://github.com/cateVM) cate#5190
	* [tinyfiledialogs](https://sourceforge.net/projects/tinyfiledialogs) cross-platform dialog box's
	* Running debug mode (Beware crashes may occur!)
)";
#else
				const std::string markdownText = u8R"(# Lua disassembler
	* [Dear ImGui](https://github.com/ocornut/imgui) a bloat-free graphical user interface library for C++
	* [ImGui markdown](https://github.com/juliettef/imgui_markdown) Markdown for Dear ImGui
	* Disassembler Made by [cateVM](https://github.com/cateVM) cate#5190
	* [tinyfiledialogs](https://sourceforge.net/projects/tinyfiledialogs) cross-platform dialog box's
	* Running Release mode
)";
#endif // DEBUG

				
				Markdown(markdownText);
				if (ImGui::Button("Close")) {
					ImGui::CloseCurrentPopup();
					about = false;
				}
				ImGui::EndPopup();
			}
			const float TEXT_BASE_WIDTH = ImGui::CalcTextSize("A").x;
			const float TEXT_BASE_HEIGHT = ImGui::GetTextLineHeightWithSpacing();
			static ImGuiTableFlags flags = ImGuiTableFlags_BordersV | ImGuiTableFlags_BordersOuterH | ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg;

			if (ImGui::TreeNode("Opcodes##Node")) {
				if (ImGui::BeginTable("InfoTable", 2, flags))
				{

					ImGui::TableSetupColumn("Opcodes##Table", ImGuiTableColumnFlags_NoHide);
					ImGui::TableSetupColumn("Constants");
					ImGui::TableHeadersRow();



					ImGui::TableNextColumn();
					bool open = ImGui::TreeNodeEx("Opcode", ImGuiTreeNodeFlags_SpanFullWidth);
					ImGui::SameLine();
					HelpMarker("This contains the \"opcodes\"/lua VM instruction/operation codes");
					if (open)
					{
						for (int i = 0; i < OpCodes.size(); i++) {

							
							if (i == OpCodes.size()-1) { //at End of opcode list sometimes theres a random opcode not sure why
								
								ImGui::TextColored(ImColor(255, 132, 132), "%d %s", i, OpCodes[i]);
								ImGui::SameLine();
								HelpMarker("Sometimes the at the end of the opcode list there is a random opcode beware!");
							}
							else if (i == 0) { // beginning of opcode list!
								ImGui::TextColored(ImColor(144, 238, 144), "%d %s", i, OpCodes[i]);
								ImGui::SameLine();
								HelpMarker("Start of opcode list");
							}
							else if (std::string(OpCodes[i]).rfind("OP_CLOSURE", 0) == 0) {
#ifdef DISASM_NO_PARSE_FUNCTION
#else
								ImGui::TextColored(ImColor(255, 182, 193), ".function %s", OpCodes[i]);
								ImGui::SameLine();
								HelpMarker("Creates an instance (or closure) of a function");
#endif // DISASM_NO_PARSE_FUNCTION

								
							}
							else if (OpCodes[i] == ".end closure") {
								ImGui::TextColored(ImColor(255, 182, 193), "%s", OpCodes[i]);
								ImGui::SameLine();
								HelpMarker("End of closure (or function)");
							}
							else {
								ImGui::Text("%d %s", i, OpCodes[i]);
							}
							
						}
						ImGui::TreePop();
					}

					ImGui::TableNextColumn();
					bool open1 = ImGui::TreeNodeEx("Constants##OpTree", ImGuiTreeNodeFlags_SpanFullWidth);
					if (open1)
					{
						for (int i = 0; i < OpCodeValues.size(); i++) {

							ImGui::TextColored(ImColor(173, 216, 230), ".const %d %s", i, OpCodeValues[i]);


						}
						ImGui::TreePop();
					}

				}
				ImGui::EndTable();
				ImGui::TreePop();
			}
			if (ImGui::TreeNode("Constants##tree")) {
				if (ImGui::BeginTable("ConstantTable", 1, flags))
				{

					ImGui::TableSetupColumn("Constants##ArabMonkey", ImGuiTableColumnFlags_NoHide);
					ImGui::TableHeadersRow();
					


					ImGui::TableNextColumn();
					bool open = ImGui::TreeNodeEx("Constants##yo", ImGuiTreeNodeFlags_SpanFullWidth);
					if (open)
					{
						for (int i = 0; i < Constants.size(); i++) {
							
							ImGui::TextColored(ImColor(173, 216, 230),".const %s", Constants[i]);
						}
						ImGui::TreePop();
					}

				}
				ImGui::EndTable();
				ImGui::TreePop();
			}
			if (ImGui::TreeNode("Additional info")) {
				ImGui::Text("--> Number of constants %d", NumOfConstants);
				ImGui::Text("--> Number of Opcodes %d", NumOfOpCodes);
				ImGui::TreePop();
			}
#ifdef DEBUG
			ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / ImGui::GetIO().Framerate, ImGui::GetIO().Framerate);
#endif // DEBUG

			mem_edit_2.DrawContents(message, 99999, (size_t)99999);
			ImGui::End();
			
		}


		// Rendering
		ImGui::Render();
		const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
		g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
		g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		// Update and Render additional Platform Windows
		if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
		{
			ImGui::UpdatePlatformWindows();
			ImGui::RenderPlatformWindowsDefault();
		}

		g_pSwapChain->Present(1, 0); // Present with vsync
		//g_pSwapChain->Present(0, 0); // Present without vsync
	}

	// Cleanup
	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();

	CleanupDeviceD3D();
	::DestroyWindow(hwnd);
	::UnregisterClass(wc.lpszClassName, wc.hInstance);
#ifdef DEBUG
	EXIT:
		exit(420);
#endif // DEBUG

	return 0;
}

// Helper functions

bool CreateDeviceD3D(HWND hWnd)
{
	// Setup swap chain
	DXGI_SWAP_CHAIN_DESC sd;
	ZeroMemory(&sd, sizeof(sd));
	sd.BufferCount = 2;
	sd.BufferDesc.Width = 0;
	sd.BufferDesc.Height = 0;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 60;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = hWnd;
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	UINT createDeviceFlags = 0;
	//createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
	D3D_FEATURE_LEVEL featureLevel;
	const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
	if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
		return false;

	CreateRenderTarget();
	return true;
}

void CleanupDeviceD3D()
{
	CleanupRenderTarget();
	if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
	if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
	if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
}

void CreateRenderTarget()
{
	ID3D11Texture2D* pBackBuffer;
	g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
	g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
	pBackBuffer->Release();
}

void CleanupRenderTarget()
{
	if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
}

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0 // From Windows SDK 8.1+ headers
#endif


extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);


LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;

	switch (msg)
	{
	case WM_SIZE:
		if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
		{
			CleanupRenderTarget();
			g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
			CreateRenderTarget();
		}
		return 0;
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
			return 0;
		break;
	case WM_DESTROY:
		::PostQuitMessage(0);
		return 0;
	case WM_DPICHANGED:
		if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports)
		{
			const RECT* suggested_rect = (RECT*)lParam;
			::SetWindowPos(hWnd, NULL, suggested_rect->left, suggested_rect->top, suggested_rect->right - suggested_rect->left, suggested_rect->bottom - suggested_rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
		}
		break;
	case WM_DROPFILES:
		auto const handle{ reinterpret_cast<::HDROP>(wParam) };
		auto const dropped_files_count
		{
			::DragQueryFileW(handle, 0xFFFFFFFF, nullptr, 0)
		};
		::std::wstring buffer;
		for (::UINT dropped_file_index{ 0 }; dropped_files_count != dropped_file_index; ++dropped_file_index)
		{
			auto const file_path_sym
			{
				::DragQueryFileW(handle, dropped_file_index, nullptr, 0)
			};
			if (0 < file_path_sym)
			{
				auto const buffer_size{ 
					file_path_sym + 1 
				};
				buffer.resize(buffer_size);
				auto const c_Symbol
				{
					::DragQueryFileW(handle, dropped_file_index, &buffer[0], buffer_size)
				};
				if (c_Symbol == file_path_sym)
				{
					buffer.back() = L'\0';
					OpCodes.clear(); // clear our opcode list
					OpCodeValues.clear(); // clear our opcode value list
					Constants.clear(); // clear our Constants list
					pseudoBytecode.str(""); // clear our pseudo Bytecode list
					memset(&message[0], 0, sizeof(message)); // clear our pseudo Bytecode char array
					NumOfConstants = 0;
					NumOfOpCodes = 0;
					lua_State* L = lua_open();
					luaL_openlibs(L);
					std::string script;
					std::ifstream ifs(buffer.c_str());
					script.assign((std::istreambuf_iterator<char>(ifs)),
						(std::istreambuf_iterator<char>()));
					LoadS ls;
					ls.s = script.c_str();
					ls.size = strlen(script.c_str());
					if (lua_load(L, getS, &ls, "@Lua_Disassembler") != LUA_OK) { // lua file errored
					ERROR_:
#ifdef DEBUG
						printf("Unable to load file details: \n%s", lua_tostring(L, -1));
#endif // DEBUG
						error = true;


					}
					else { // LUA_OK
						OpenedFile = _strdup(_bstr_t(buffer.c_str()));
						{
						PARSE:
							TValue* top = L->top - 1; // get the object at the top of the lua stack
							LClosure* func = (LClosure*)(top->value.gc); // interpret this object as an LClosure*
							Proto* p = func->p; // Grab our needed Proto from this pointer

							auto* disassembler = new disasm;
							disassembler->GetConstants(L, Constants);
							disassembler->parse(p, L, pseudoBytecode, NumOfOpCodes, NumOfConstants, OpCodeValues, OpCodes);
							delete disassembler;
#ifdef DEBUG
							std::cout << "\n ---- OUTPUT OF FILE ----" << std::endl;
#endif // DEBUG


							//lua_pcall(L, 0,0,0);
#ifdef DEBUG
							dumpstack(L);
#endif // DEBUG


							lua_close(L);
#ifdef DEBUG
							printf("size of opcode vector -> %d", OpCodes.size());
#endif
						}


					}
					std::string pseudoBytecode_s = pseudoBytecode.str();

					message[0] = '\0';

					for (int i = 0; i < pseudoBytecode_s.length(); i++) {
						char c[6];
						sprintf(c, "%02X ", (BYTE)pseudoBytecode_s[i]);
						strcat(message, c);
						if (i + 1 % 12 == 0) {
							strcat(message, "\n");
						}
					}
#ifdef DEBUG
					std::cout << message << std::endl;
#endif
				}
				}
			}
		
		break;
	}
	return ::DefWindowProc(hWnd, msg, wParam, lParam);
}