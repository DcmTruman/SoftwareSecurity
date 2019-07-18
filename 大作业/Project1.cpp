//#include <stdafx.h>

#pragma comment(lib,"OpenGL32.lib")
#pragma comment(lib,"GLu32.lib")

#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include <fstream>
#include <cstdio>
#include <gl\gl.h>
#include <gl\glu.h>

typedef void (APIENTRY *glBegin_t)(GLenum);
glBegin_t pglBegin = NULL;
bool x_ray = true;
HANDLE cs_hProcess;
HWND cs_hwnd;
DWORD cs_dwPID, ptr, ptr1, ptr2;
DWORD value;
void money_init()
{
	cs_hwnd = FindWindow(NULL, L"Counter-Strike");
	GetWindowThreadProcessId(cs_hwnd, &cs_dwPID);
	cs_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, cs_dwPID);
	ptr = (0x11069BC + 0x1400000);
	
	x_ray = true;
}


void change_money() {
	ReadProcessMemory(cs_hProcess, (DWORD*)ptr, &ptr1, 4, NULL);
	ptr1 += 0x7c;
	ReadProcessMemory(cs_hProcess, (DWORD*)ptr1, &ptr2, 4, NULL);
	ptr2 += 0x1cc;
	value = 999999;
	WriteProcessMemory(cs_hProcess, (DWORD*)ptr2, &value, 4, NULL);
}

void APIENTRY hook_glBegin(GLenum mode) {
	//if push F1_key
	if (GetAsyncKeyState(VK_F1) & 1) x_ray ^= 1;
	if (x_ray) {
		if (mode == GL_TRIANGLES || mode == GL_TRIANGLE_STRIP || mode == GL_TRIANGLE_FAN)
			glDepthRange(0, 0.5);
		else
			glDepthRange(0.5, 1);
	}
	change_money();
	if (pglBegin)
		(*pglBegin)(mode);
}



void * get_new_func(BYTE *old_en, const BYTE *my_func, const int block_len)
{
	BYTE *new_en = (BYTE*)malloc(block_len + 5);
	DWORD temp;
	//able to write my own program 
	VirtualProtect(old_en , block_len, PAGE_READWRITE, &temp);
	memcpy(new_en, old_en, block_len);
	new_en += block_len;
	new_en[0] = old_en[0] =  0xE9;
	*(DWORD*)(new_en+ 1) = (DWORD)(old_en + block_len- new_en) - 5; 
	*(DWORD*)(old_en+ 1) = (DWORD)(my_func- old_en) - 5; 
	VirtualProtect(old_en, block_len, temp, &temp); 
	return (new_en - block_len); 
}
void HookOpenGL() {
	HMODULE hOpenGL = GetModuleHandle(L"opengl32.dll");
	pglBegin = (glBegin_t)get_new_func((LPBYTE)GetProcAddress(hOpenGL, "glBegin"), (LPBYTE)&hook_glBegin, 6);
}

DWORD WINAPI dwMainThread(LPVOID) {
	money_init();
	HookOpenGL();
	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH)
		CreateThread(0, 0, dwMainThread, 0, 0, 0);
	return TRUE;
}

