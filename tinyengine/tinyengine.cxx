extern "C" {
    int _fltused = 0;

    //void __std_terminate() {

    //}

    //void __CxxFrameHandler4() {

    //}
}
//#define WIN32_LEAN_AND_MEAN
//#include <windows.h>

typedef int i32;
typedef short i16;
typedef signed char i8;
typedef unsigned u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef float f32;
typedef double f64;


using WORD = unsigned short;
using DWORD = unsigned long;
using BYTE = unsigned char;

typedef struct tagPIXELFORMATDESCRIPTOR {
    WORD  nSize;
    WORD  nVersion;
    DWORD dwFlags;
    BYTE  iPixelType;
    BYTE  cColorBits;
    BYTE  cRedBits;
    BYTE  cRedShift;
    BYTE  cGreenBits;
    BYTE  cGreenShift;
    BYTE  cBlueBits;
    BYTE  cBlueShift;
    BYTE  cAlphaBits;
    BYTE  cAlphaShift;
    BYTE  cAccumBits;
    BYTE  cAccumRedBits;
    BYTE  cAccumGreenBits;
    BYTE  cAccumBlueBits;
    BYTE  cAccumAlphaBits;
    BYTE  cDepthBits;
    BYTE  cStencilBits;
    BYTE  cAuxBuffers;
    BYTE  iLayerType;
    BYTE  bReserved;
    DWORD dwLayerMask;
    DWORD dwVisibleMask;
    DWORD dwDamageMask;
} PIXELFORMATDESCRIPTOR, *PPIXELFORMATDESCRIPTOR, *LPPIXELFORMATDESCRIPTOR;

using HANDLE = void*;
using HINSTANCE = HANDLE;
using HMODULE = HANDLE;
using HDC = HANDLE;
using BOOL = BYTE;
using LPCSTR = const char*;
using LPDWORD = DWORD*;
using VOID = void;
using LPVOID = void*;
using LONG = long;
using PLONG = long*;
using HWND = HANDLE;

using ATOM = WORD;

using ULONG_PTR = unsigned long;
using PVOID = void*;

typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union {
        struct {
            DWORD Offset;
            DWORD OffsetHigh;
        } DUMMYSTRUCTNAME;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    HANDLE    hEvent;
} OVERLAPPED, * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES {
    DWORD  nLength;
    LPVOID lpSecurityDescriptor;
    BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, * PSECURITY_ATTRIBUTES, * LPSECURITY_ATTRIBUTES;

using UINT = unsigned;

typedef struct tagPOINT {
    LONG x;
    LONG y;
} POINT, * PPOINT, * NPPOINT, * LPPOINT;

using LPARAM = long;
using WPARAM = unsigned;
using LRESULT = long;

typedef struct tagMSG {
    HWND   hwnd;
    UINT   message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD  time;
    POINT  pt;
    DWORD  lPrivate;
} MSG, * PMSG, * NPMSG, * LPMSG;

using HICON = void*;
using HCURSOR = void*;
using HBRUSH = void*;
using WNDPROC = LRESULT(*)(HWND, UINT, WPARAM, LPARAM);
using HMENU = void*;
using HGLRC = void*;

//typedef LRESULT (WNDPROC)(HWND, UINT, WPARAM, LPARAM);


HMODULE (__stdcall *LoadLibraryA)(LPCSTR) = 0;
using FARPROC = void*;
FARPROC(__stdcall *GetProcAddress)(HMODULE, LPCSTR) = 0;

using SIZE_T = unsigned long;

typedef struct tagWNDCLASSA {
    UINT      style;
    WNDPROC   lpfnWndProc;
    int       cbClsExtra;
    int       cbWndExtra;
    HINSTANCE hInstance;
    HICON     hIcon;
    HCURSOR   hCursor;
    HBRUSH    hbrBackground;
    LPCSTR    lpszMenuName;
    LPCSTR    lpszClassName;
} WNDCLASSA, * PWNDCLASSA, * NPWNDCLASSA, * LPWNDCLASSA;


typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic; // Magic number
    WORD e_cblp; // Bytes on last page of file
    WORD e_cp; // Pages in file
    WORD e_crlc; // Relocations
    WORD e_cparhdr; // Size of header in paragraphs
    WORD e_minalloc; // Minimum extra paragraphs needed
    WORD e_maxalloc; // Maximum extra paragraphs needed
    WORD e_ss; // Initial (relative) SS value
    WORD e_sp; // Initial SP value
    WORD e_csum; // Checksum
    WORD e_ip; // Initial IP value
    WORD e_cs; // Initial (relative) CS value
    WORD e_lfarlc; // File address of relocation table
    WORD e_ovno; // Overlay number
    WORD e_res[4]; // Reserved words
    WORD e_oemid; // OEM identifier (for e_oeminfo)
    WORD e_oeminfo; // OEM information; e_oemid specific
    WORD e_res2[10]; // Reserved words
    LONG e_lfanew; // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;


using UINT32 = unsigned long;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16


typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, * PIMAGE_NT_HEADERS;

static HMODULE findModuleBase(void* ptr)
{
    ULONG_PTR addr = (ULONG_PTR)ptr;
    addr &= ~0xffff;
    const UINT32* mod = (const UINT32*)addr;
    while (mod[0] != 0x00905a4d) // MZ.. header
        mod -= 0x4000; // 0x10000/4
    return ((HMODULE)mod);
}

#define REL_PTR(base, ofs) (((PBYTE)base) + ofs)

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA to array of function RVAs
    DWORD   AddressOfNames;         // RVA to array of name RVAs
    DWORD   AddressOfNameOrdinals;  // RVA to array of WORD ordinals
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;


#define IMAGE_DIRECTORY_ENTRY_EXPORT 0

#define REL_PTR(base, offset) ((PVOID)((BYTE*)(base) + (DWORD)(offset)))


using UINT8 = unsigned char;
using UINT16 = unsigned short;

static void* findGetProcAddress(HMODULE mod)
{
    PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS inh = (PIMAGE_NT_HEADERS)REL_PTR(idh, idh->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)REL_PTR(
        idh,
        inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        .VirtualAddress);
    DWORD* names = (DWORD*)REL_PTR(idh, ied->AddressOfNames);
    unsigned int i;
    for (i = 0; i < ied->NumberOfNames; i++) {
        const UINT32* name32 = (const UINT32*)REL_PTR(idh, names[i]);
        const UINT16* name16 = (const UINT16*)name32;
        const UINT8* name8 = (const UINT8*)name32;
        if (name32[0] != 0x50746547 || // GetP
            name32[1] != 0x41636f72 || // rocA
            name32[2] != 0x65726464 || // ddre
            name16[6] != 0x7373 || // ss
            name8[14] != 0x00)
            continue;
        WORD* ordinals =
            (WORD*)REL_PTR(idh, ied->AddressOfNameOrdinals);
        DWORD* funcs = (DWORD*)REL_PTR(idh, ied->AddressOfFunctions);
        return (REL_PTR(idh, funcs[ordinals[i]]));
    }
    return (0);
}

void* __cdecl _ReturnAddress() {
    __asm {
        mov eax, dword ptr ss:[ebp + 4]
        ret
    }
}

#define RETURN_ADDRESS() _ReturnAddress()



void getLoadLibraryA() {
    /*__asm {

xor ebx, ebx

mov edi, fs:[0x30]
mov edi, [edi + 0x0c]
mov edi, [edi + 0x1c]

module_loop:
mov eax, [edi + 0x18]
    mov esi, [edi + 0x20]
    mov edi, [edi]
    cmp byte ptr [esi + 12], '3'
jne module_loop

mov edi, eax
add edi, [eax + 0x3c]

mov edx, [edi + 0x78]
add edx, eax

mov edi, [edx + 0x20]
add edi, eax

mov ebp, ebx
name_loop :
mov esi, [edi + ebp * 4]
add esi, eax
inc ebp
cmp dword ptr [esi], 0x50746547
jne name_loop
cmp dword ptr[esi + 8], 0x65726464
jne name_loop

mov edi, [edx + 0x24]
add edi, eax
mov bp, [edi + ebp * 2]

mov edi, [edx + 0x1C]
add edi, eax
mov edi, [edi + (ebp - 1) * 4]
add edi, eax

mov dword ptr[GetProcAddress], edi

push 0x00000000
push 0x41797261
push 0x7262694C
push 0x64616F4C
push esp

push eax
xchg eax, esi
call edi

mov dword ptr [LoadLibraryA], eax

    }*/

    HMODULE kernel = findModuleBase(RETURN_ADDRESS());

    GetProcAddress = (decltype(GetProcAddress))findGetProcAddress(kernel);

    LoadLibraryA = (decltype(LoadLibraryA))GetProcAddress(kernel, "LoadLibraryA");
}

namespace w32 {

#define K32(a, b) P32 = (void*)GetProcAddress(kernmod, b); a = (decltype(a))P32;
#define U32(a, b) P32 = (void*)GetProcAddress(usermod, b); a = (decltype(a))P32;
#define G32(a, b) P32 = (void*)GetProcAddress(gdimod, b); a = (decltype(a))P32;

    int (*ChoosePixelFormat)(HDC, PPIXELFORMATDESCRIPTOR);
    BOOL (*SetPixelFormat)(HDC, int, PPIXELFORMATDESCRIPTOR);
    int (*DescribePixelFormat)(HDC, int, unsigned long long, PPIXELFORMATDESCRIPTOR);
    BOOL (*SwapBuffers)(HDC);
    HANDLE (*CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    DWORD (*GetFileSize)(HANDLE, LPDWORD);
    BOOL (*ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    DWORD (*SetFilePointer)(HANDLE, LONG, PLONG, DWORD);
    BOOL(*TranslateMessage)(const MSG*);
    BOOL(*DispatchMessageA)(const MSG*);
    BOOL(*PeekMessageA)(LPMSG, HWND, UINT, UINT, UINT);
    HMODULE(*GetModuleHandleA)(LPCSTR);
    ATOM(*RegisterClassA)(const WNDCLASSA *);
    HDC(*GetDC)(HWND);
    HWND(*CreateWindowExA)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);

    LPVOID(*HeapAlloc)(HANDLE, DWORD, SIZE_T);
    BOOL(*HeapFree)(HANDLE, DWORD, LPVOID);
    HANDLE(*GetProcessHeap)();
    VOID(*ExitProcess)(UINT);

    LRESULT(*DefWindowProcA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);


    BOOL(*ShowWindow)(HWND, int);

    void loadWin32() {
        getLoadLibraryA();


        static HMODULE kernmod, usermod, gdimod;
        void* P32;
        kernmod = LoadLibraryA("kernel32.dll");
        usermod = LoadLibraryA("user32.dll");
        gdimod = LoadLibraryA("gdi32.dll");

        G32(ChoosePixelFormat, "ChoosePixelFormat");
        G32(SetPixelFormat, "SetPixelFormat");
        G32(DescribePixelFormat, "DescribePixelFormat");
        G32(SwapBuffers, "SwapBuffers");
        K32(CreateFileA, "CreateFileA");
        K32(SetFilePointer, "SetFilePointer");
        U32(TranslateMessage, "TranslateMessage");
        U32(DispatchMessageA, "DispatchMessageA");
        U32(PeekMessageA, "PeekMessageA");
        U32(ShowWindow, "ShowWindow");
        U32(DefWindowProcA, "DefWindowProcA");
        K32(GetModuleHandleA, "GetModuleHandleA");
        U32(RegisterClassA, "RegisterClassA");
        U32(GetDC, "GetDC");
        U32(CreateWindowExA, "CreateWindowExA");

        K32(HeapAlloc, "HeapAlloc");
        K32(HeapFree, "HeapFree");
        K32(GetProcessHeap, "GetProcessHeap");
        K32(ExitProcess, "ExitProcess");

    }

}

namespace gl {

    void (*viewport)(u32, u32, u32, u32);
    void (*clear)(u32);
    void (*clearColor)(f32, f32, f32, f32);

    void (*genBuffers)(u32, u32*);
    void (*bindBuffer)(u32, u32);
    void (*bufferData)(u32, u32, const void*, u32);

    void (*genVertexArrays)(u32, u32*);
    void (*bindVertexArray)(u32);
    void (*enableVertexAttribArray)(u32);
    void (*vertexAttribPointer)(u32, i32, u32, bool, u32, const void*);

    void (*drawElements)(u32, u32, u32, const void*);

    void (*genTextures)(u32, u32*);
    void (*bindTexture)(u32, u32);
    void (*texParameteri)(u32, u32, i32);
    void (*texImage2D)(u32, i32, i32, u32, u32, i32, u32, u32, const void*);
    void (*generateMipmap)(u32);


    u32(*createShader)(u32);
    u32(*shaderSource)(u32, u32, const char**, const i32*);
    u32(*compileShader)(u32);

    u32(*createProgram)();
    u32(*attachShader)(u32, u32);
    u32(*linkProgram)(u32);
    void (*useProgram)(u32);

    i32(*getUniformLocation)(u32, const char*);
    void (*uniformMatrix4fv)(i32, i32, bool, float*);
    void (*uniform1i)(i32, i32);

    long long (*wGetProcAddress)(const char*);
    HGLRC(*wCreateContext)(HDC);
    BOOL(*wMakeCurrent)(HDC, HGLRC);

    void (*genFramebuffers)(u32, u32*);
    void (*bindFramebuffer)(u32, u32);
    void (*framebufferTexture2D)(u32, u32, u32, u32, i32);

    HMODULE glmod;
    void* loadFunc(const char* name) {
        void* p = (void*)wGetProcAddress(name);
        if (p == 0 ||
            p == (void*)0x1 ||
            p == (void*)0x2 ||
            p == (void*)0x3 ||
            p == (void*)-1) {
            p = (void*)GetProcAddress(glmod, name);
        }
        return p;
    }

#define GL_LOADFUNC(a, b) a = (decltype(a))loadFunc(b)

    void preinit() {
        glmod = LoadLibraryA("opengl32.dll");
        void* p = (void*)GetProcAddress(glmod, "wglGetProcAddress");
        wGetProcAddress = (decltype(wGetProcAddress))p;

        p = (void*)GetProcAddress(glmod, "wglCreateContext");
        wCreateContext = (decltype(wCreateContext))p;

        p = (void*)GetProcAddress(glmod, "wglMakeCurrent");
        wMakeCurrent = (decltype(wMakeCurrent))p;
    }

    void init() {
        GL_LOADFUNC(viewport, "glViewport");
        GL_LOADFUNC(clear, "glClear");
        GL_LOADFUNC(clearColor, "glClearColor");
        GL_LOADFUNC(createShader, "glCreateShader");
        GL_LOADFUNC(shaderSource, "glShaderSource");
        GL_LOADFUNC(compileShader, "glCompileShader");

        GL_LOADFUNC(createProgram, "glCreateProgram");
        GL_LOADFUNC(attachShader, "glAttachShader");
        GL_LOADFUNC(linkProgram, "glLinkProgram");
        GL_LOADFUNC(useProgram, "glUseProgram");

        GL_LOADFUNC(genBuffers, "glGenBuffers");
        GL_LOADFUNC(bindBuffer, "glBindBuffer");
        GL_LOADFUNC(bufferData, "glBufferData");

        GL_LOADFUNC(genVertexArrays, "glGenVertexArrays");
        GL_LOADFUNC(bindVertexArray, "glBindVertexArray");
        GL_LOADFUNC(vertexAttribPointer, "glVertexAttribPointer");
        GL_LOADFUNC(enableVertexAttribArray, "glEnableVertexAttribArray");

        GL_LOADFUNC(drawElements, "glDrawElements");

        GL_LOADFUNC(getUniformLocation, "glGetUniformLocation");
        GL_LOADFUNC(uniformMatrix4fv, "glUniformMatrix4fv");
        GL_LOADFUNC(uniform1i, "glUniform1i");

        GL_LOADFUNC(genTextures, "glGenTextures");
        GL_LOADFUNC(bindTexture, "glBindTexture");
        GL_LOADFUNC(texParameteri, "glTexParameteri");
        GL_LOADFUNC(texImage2D, "glTexImage2D");
        GL_LOADFUNC(generateMipmap, "glGenerateMipmap");

        GL_LOADFUNC(genFramebuffers, "glGenFramebuffers");
        GL_LOADFUNC(bindFramebuffer, "glBindFramebuffer");
        GL_LOADFUNC(framebufferTexture2D, "glFramebufferTexture2D");
    }
};

template <typename T, unsigned long long size>
struct Array {
    T data[size];
    T& operator[] (size_t i) {
        return data[i];
    }
};

struct ShaderProgram {
    void init(const char* vsrc, const char* fsrc) {
        id = gl::createProgram();
        u32 vid = loadShader(vsrc, 0x8B31);
        u32 fid = loadShader(fsrc, 0x8B30);
        gl::attachShader(id, vid);
        gl::attachShader(id, fid);
        gl::linkProgram(id);
    }

    void use() {
        gl::useProgram(id);
    }

    static u32 loadShader(const char* src, u32 type) {
        u32 i = gl::createShader(type);
        gl::shaderSource(i, 1, &src, nullptr);
        gl::compileShader(i);
        return i;
    }
    u32 id;
};

u8* readFile(const char* path) {
    HANDLE f = w32::CreateFileA(path, 0x80000000L, 0x00000001, 0, 4, 0x00000080, 0);
    w32::SetFilePointer(f, 0, 0, 0);
    DWORD fsize = w32::GetFileSize(f, 0);

    u8* cont = new u8[fsize];

    DWORD numRead;
    
    w32::ReadFile(f, cont, fsize, &numRead, 0);

    return cont;
}

struct Texture {
    void init(const char* path) {
        u8* cont = readFile(path);

        u32 w = *(i32*)((cont + 0x12));
        u32 h = *(i32*)((cont + 0x16));
        u32 siz = *(i32*)((cont + 0x22)); if (!siz) siz = w * h * 3;
        u32 dpos = *(i32*)((cont + 0x0a)); if (!dpos) dpos = 54;

        u8* data = cont + dpos;

        gl::genTextures(1, &id);
        gl::bindTexture(0x0de1, id);

        gl::texImage2D(0x0de1, 0, 0x80e1, w, h, 0, 0x80e1, 0x1401, data);

        gl::texParameteri(0x0de1, 0x2802, 0x8370); //el problemo
        gl::texParameteri(0x0de1, 0x2803, 0x8370);// biEn?
        gl::texParameteri(0x0de1, 0x2800, 0x2600);
        gl::texParameteri(0x0de1, 0x2801, 0x2701);

        gl::generateMipmap(0x0de1);

        operator delete (cont);
    }

    void use(ShaderProgram& sh) const {
        gl::bindTexture(0x0de1, id);
        // gl::uniform1i(gl::getUniformLocation(sh.id, "stex"), id);
    }
    u32 id;
};

struct Mesh {

    template <size_t NV, size_t NI>
    void init(const Array<float, NV>& verts, const Array<unsigned, NI>& inds, const Array<float, NV * 3 / 2>& texcs) {
        i_ct = static_cast<u32>(NI);
        gl::genVertexArrays(1, &vao);
        gl::bindVertexArray(vao);
        gl::genBuffers(1, &vbo);
        gl::genBuffers(1, &ebo);
        gl::genBuffers(1, &tbo);
        gl::bindBuffer(0x8892, vbo);
        gl::bufferData(0x8892, sizeof(verts), &(verts.data[0]), 0x88e4);

        gl::enableVertexAttribArray(0);
        gl::vertexAttribPointer(0, 3, 0x1406, false, sizeof(float) * 3, (void*)0);

        gl::bindBuffer(0x8892, tbo);
        gl::bufferData(0x8892, sizeof(texcs), &(texcs.data[0]), 0x88e4);

        gl::enableVertexAttribArray(1);
        gl::vertexAttribPointer(1, 2, 0x1406, false, sizeof(float) * 2, (void*)0);

        gl::bindBuffer(0x8893, ebo);
        gl::bufferData(0x8893, sizeof(inds), &(inds.data[0]), 0x88e4);


    }

    void draw(const ShaderProgram&) {
        gl::drawElements(0x0004, i_ct, 0x1405, 0);
    }

    u32 vao, vbo, ebo, tbo;
    u32 i_ct;
};

static Mesh THEQUAD;

struct Sprite {
    void init() {

    }
    void draw(const ShaderProgram& shader_program) {

        THEQUAD.draw(shader_program);
    }
    Array<float, 2> position;
    float mat[16];
};

struct Surface {

    void init(int _width = 480, int _height = 480) {
        this->width = _width;
        this->height = _height;
    }

    int width, height;
};

struct Window {
    void init(const char title[] = "Tiny Engine", int _width = 480, int _height = 480) {
        this->width = _width;
        this->height = _height;
        active = this;
        should_close = false;
        HINSTANCE inst = w32::GetModuleHandleA(0);
        wc.style = 0x0002 | 0x0001 | 0x0020;
        wc.lpfnWndProc = procedure;
        wc.hInstance = inst;
        wc.lpszClassName = title;
        w32::RegisterClassA(&wc);

        h = w32::CreateWindowExA(
            0,
            title,
            title,
            (0x00000000L | 0x00C00000L | 0x00080000L | 0x00040000L | 0x00020000L | 0x00010000L) | 0x02000000L,
            ((int)0x80000000), ((int)0x80000000),
            width, height,
            0,
            0,
            inst,
            0
        );

        PIXELFORMATDESCRIPTOR ppfd;
        ppfd = {
            .nSize = sizeof(ppfd),
            .nVersion = 1,
            .dwFlags = 0x00000004 | 0x00000020 | 0x00000001,
            .iPixelType = 0,
            .cColorBits = 24,
            .cAlphaBits = 8,
            .cDepthBits = 24,
            .cStencilBits = 8,
            .iLayerType = 0
        };

        hdc = w32::GetDC(h);
        int format = w32::ChoosePixelFormat(hdc, &ppfd);

        w32::SetPixelFormat(hdc, format, &ppfd);
        w32::DescribePixelFormat(hdc, format, sizeof(PIXELFORMATDESCRIPTOR), &ppfd);


    }

    void makeContextCurrent() {
        hglrc = gl::wCreateContext(hdc);
        gl::wMakeCurrent(hdc, hglrc);
        w32::ShowWindow(h, 5);
    }

    WNDCLASSA wc;
    HWND h;
    HDC hdc;
    HGLRC hglrc;

    static LRESULT procedure(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
        switch (Msg) {
        case 0x0100:
            if (active->onKeyDown != nullptr) {
                active->onKeyDown(static_cast<int>(wParam));
            }
            return 0;
        case 0x0101:
            if (active->onKeyUp != nullptr) {
                active->onKeyUp(static_cast<int>(wParam));
            }
            return 0;
        case 0x0010:
            active->should_close = true;
            return 0;
        }
        return w32::DefWindowProcA(hWnd, Msg, wParam, lParam);
    }

    void (*onKeyDown)(int code) = nullptr;
    void (*onKeyUp)(int code) = nullptr;

    int width, height;
    bool should_close;

    void update() {
        static MSG msg;
        //
        if (w32::PeekMessageA(&msg, h, 0, 0, 0x0001)) {
            w32::TranslateMessage(&msg);
            w32::DispatchMessageA(&msg);
        }
        w32::SwapBuffers(hdc);
    }

    inline static Window* active;
};



struct Game {
    Window window;

    int run() {

        window.init("Tiny Game", 480, 360);
        gl::preinit();
        window.makeContextCurrent();
        gl::init();

        window.onKeyDown = [](int) {

            };
        window.onKeyUp = [](int) {

            };

        gl::viewport(0, 0, 480, 360);
        gl::clearColor(0.2f, 0.4f, 0.5f, 1.0f);

        THEQUAD.init<12, 6>(
            {
                -1.0f, -1.0f, 0.0f,
                -1.0f, 1.0f, 0.0f,
                1.0f, 1.0f, 0.0f,
                1.0f, -1.0f, 0.0f,
            },
            {
                0, 1, 2,
                0, 2, 3,
            },
            {
                0.0f, 0.0f,
                0.0f, 1.0f,
                1.0f, 1.0f,
                1.0f, 0.0f,
            }
            );

        Sprite triangle;
        triangle.init();

        const char* vsrc = "\
        layout (location = 0) in vec3 a_pos;\
        layout (location = 1) in vec2 a_tex;\
        uniform mat4 projection;\
        out vec2 texcs;\
        void main() {\
            gl_Position = projection * vec4(a_pos, 1.0);\
            texcs = a_tex;\
        }";
        const char* fsrc = "\
        uniform sampler2D stex;\
        in vec2 texcs;\
        void main() {\
            gl_FragColor = texture(stex, texcs);\
        }";
        ShaderProgram sh;
        sh.init(vsrc, fsrc);

        Texture testt;
        testt.init("../pixil-frame-0.bmp");

        float projection_matrix[] = {
            100 / 480.0f, 0, 0, 0,
            0, 100 / 360.0f, 0, 0,
            0, 0, 1, 0,
            0, 0, 0, 1
        };

        float fb_projection_matrix[] = {
            1,0,0,0,
            0,1,0,0,
            0,0,1,0,
            0,0,0,1,
        };



        u32 fbo;
        gl::genFramebuffers(1, &fbo);
        gl::bindFramebuffer(0x8d40, fbo);

        Texture fbt;
        gl::genTextures(1, &(fbt.id));
        gl::bindTexture(0xde1, fbt.id);
        gl::texImage2D(0xde1, 0, 0x1907, 480, 360, 0, 0x1907, 0x1401, 0);

        gl::texParameteri(0xde1, 0x2801, 0x2601);
        gl::texParameteri(0xde1, 0x2800, 0x2601);


        gl::framebufferTexture2D(0x8d40, 0x8ce0, 0xde1, fbt.id, 0);

        gl::bindFramebuffer(0x8d40, 0);

        while (!window.should_close) {
            gl::clear(0x00004000);
            sh.use();
            testt.use(sh);
            gl::bindFramebuffer(0x8d40, fbo);
            gl::uniformMatrix4fv(gl::getUniformLocation(sh.id, "projection"), 1, false, &projection_matrix[0]);

            triangle.draw(sh);

            gl::bindTexture(0xde1, fbt.id);
            gl::bindFramebuffer(0x8d40, 0);
            gl::uniformMatrix4fv(gl::getUniformLocation(sh.id, "projection"), 1, false, &fb_projection_matrix[0]);
            THEQUAD.draw(sh);
            window.update();
        }
        return 0;
    }

};

static HANDLE PROCHEAP;

void* operator new (unsigned int size) {
    
    return w32::HeapAlloc(
        PROCHEAP,
        0,
        size
    );
}

void* operator new[](unsigned int size) {
    return w32::HeapAlloc(
        PROCHEAP,
        0,
        size
    );
}

void operator delete(void* ob) {
    w32::HeapFree(
        PROCHEAP,
        0,
        ob
    );
}

void operator delete(void* ob, unsigned long long size) {
    w32::HeapFree(
        PROCHEAP,
        0,
        ob
    );
}



//extern "C" void WinMainCRTStartup() {
extern "C" {

    void*  memset(void* b, int c, int len) {
        int i;
        unsigned char* p = (unsigned char*)b;
        while (len > 0) {
            *p = c;
            p++;
            len--;
        }
        return(b);
    }

    void mian() {
        w32::loadWin32();
        PROCHEAP = w32::GetProcessHeap();
        Game* game = new Game();
        int ret = game->run();
        w32::ExitProcess(ret);
    }

}