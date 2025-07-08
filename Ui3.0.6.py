import PySimpleGUI as sg
import os
import sys
import threading
import subprocess 
import re
import ctypes
import time
import uuid

setupapi = ctypes.windll.LoadLibrary("SetupAPI.dll")


DIGCF_PRESENT = 0x00000002
DIGCF_DEVICEINTERFACE = 0x00000010
INVALID_HANDLE_VALUE = -1
SPDRP_DEVICEDESC = 0x00000000 

TARGET_VID_PIDS = {
    'VID_1A86&PID_55DB': 'CH347T',  # CH347t
    'VID_1A86&PID_55DE': 'CH347F',  # CH347F
    'VID_1A86&PID_5512': 'CH341A',  # CH341A
}

class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8)]

class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_ulong),
                ("ClassGuid", GUID),
                ("DevInst", ctypes.c_ulong),
                ("Reserved", ctypes.c_void_p)]

class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_ulong),
                ("InterfaceClassGuid", GUID),
                ("Flags", ctypes.c_ulong),
                ("Reserved", ctypes.c_void_p)]

setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong]
setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p

setupapi.SetupDiEnumDeviceInfo.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(SP_DEVINFO_DATA)]
setupapi.SetupDiEnumDeviceInfo.restype = ctypes.c_bool

setupapi.SetupDiGetDeviceInstanceIdW.argtypes = [ctypes.c_void_p, ctypes.POINTER(SP_DEVINFO_DATA), ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
setupapi.SetupDiGetDeviceInstanceIdW.restype = ctypes.c_bool

setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
setupapi.SetupDiDestroyDeviceInfoList.restype = ctypes.c_bool

setupapi.SetupDiGetDeviceRegistryPropertyW.argtypes = [ctypes.c_void_p, ctypes.POINTER(SP_DEVINFO_DATA), ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
setupapi.SetupDiGetDeviceRegistryPropertyW.restype = ctypes.c_bool

def guid_from_string(guid_str):
    guid = uuid.UUID(guid_str)
    return GUID(
        Data1=guid.time_low,
        Data2=guid.time_mid,
        Data3=guid.time_hi_version,
        Data4=(ctypes.c_ubyte * 8)(*bytearray(guid.bytes[8:]))
    )

def get_device_description(h_dev_info, dev_info_data):
    property_reg_dtype = ctypes.c_ulong(0)
    required_size = ctypes.c_ulong(0)

    setupapi.SetupDiGetDeviceRegistryPropertyW(h_dev_info, ctypes.byref(dev_info_data), SPDRP_DEVICEDESC,
                                               ctypes.byref(property_reg_dtype), None, 0, ctypes.byref(required_size))

    if required_size.value > 0:
        buffer = ctypes.create_unicode_buffer(required_size.value)
        if setupapi.SetupDiGetDeviceRegistryPropertyW(h_dev_info, ctypes.byref(dev_info_data), SPDRP_DEVICEDESC,
                                                      ctypes.byref(property_reg_dtype), buffer, required_size.value,
                                                      None):
            return buffer.value

    return "Unknown Device"

def get_connected_devices():
    devices = {}
    try:
        guid = guid_from_string("{A5DCBF10-6530-11D2-901F-00C04FB951ED}")
        h_dev_info = setupapi.SetupDiGetClassDevsW(ctypes.byref(guid), None, None,
                                                   DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)

        if h_dev_info == INVALID_HANDLE_VALUE:
            raise RuntimeError("Failed to get device information set.")

        try:
            dev_info_data = SP_DEVINFO_DATA()
            dev_info_data.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
            index = 0
            while True:
                if not setupapi.SetupDiEnumDeviceInfo(h_dev_info, index, ctypes.byref(dev_info_data)):
                    break

                buffer_size = 250
                buffer = ctypes.create_unicode_buffer(buffer_size)
                required_size = ctypes.c_ulong(0)
                if setupapi.SetupDiGetDeviceInstanceIdW(h_dev_info, ctypes.byref(dev_info_data), buffer, buffer_size,
                                                        ctypes.byref(required_size)):
                    device_id = buffer.value
                    for vid_pid, name in TARGET_VID_PIDS.items():
                        if vid_pid in device_id:
                            description = get_device_description(h_dev_info, dev_info_data)
                            devices[device_id] = (name, description)
                            break

                index += 1
        finally:
            setupapi.SetupDiDestroyDeviceInfoList(h_dev_info)
    except Exception as e:
        pass

    return devices

class DeviceMonitor:
    def __init__(self, window):
        self.window = window
        self.previous_devices = {}
        threading.Thread(target=self.monitor_device_changes, daemon=True).start()

    def update_status_bar(self, message):
        self.window.write_event_value('-DEVICE_CHANGE-', message)

    def monitor_device_changes(self):
        self.perform_initial_scan()
        while True:
            time.sleep(2)  # 每2秒检查一次
            try:
                current_devices = get_connected_devices()
                new_devices = {k: v for k, v in current_devices.items() if k not in self.previous_devices}
                removed_devices = {k: v for k, v in self.previous_devices.items() if k not in current_devices}

                messages = []
                for device_id, (name, description) in new_devices.items():
                    messages.append(f" {name} ：已连接")
                for device_id, (name, description) in removed_devices.items():
                    messages.append(f" {name} ：已断开")

                if messages:
                    status_message = " | ".join(messages)
                    self.update_status_bar(status_message)

                self.previous_devices = current_devices.copy()
            except Exception as e:
                self.update_status_bar(f"An error occurred: {e}")

    def perform_initial_scan(self):
        try:
            initial_devices = get_connected_devices()
            status_message = ""
            if initial_devices:
                for device_id, (name, description) in initial_devices.items():
                    status_message += f" {name} ：已连接"
            else:
                status_message += "没有检测到设备"
            self.update_status_bar(status_message)
            self.previous_devices = initial_devices.copy()
        except Exception as e:
            self.update_status_bar(f"An error occurred during initial scan: {e}")

def get_hex_dump(file_path, offset=0, length=524288):
    try:
        with open(file_path, 'rb') as f:
            f.seek(offset)
            data = f.read(length)
        bytes_per_line = 10
        byte_width = 2 
        space_between_bytes = 1
        total_byte_width = bytes_per_line * (byte_width + space_between_bytes) - space_between_bytes
        ascii_width = bytes_per_line
        hex_header = ' '.join(f'{i:02X}' for i in range(bytes_per_line))
        header = f"Address: {hex_header}    ASCII"
        separator = "--------+" + "-" * total_byte_width + "+" + "-" * ascii_width
        formatted_output = [header, separator]
        for line_num, i in enumerate(range(0, len(data), bytes_per_line)):
            chunk = data[i:i + bytes_per_line]
            addr = f"{offset + (line_num * bytes_per_line):08X}"
            hex_values = ['{:02X}'.format(byte) for byte in chunk]
            while len(hex_values) < bytes_per_line:
                hex_values.append('  ') 
            ascii_chars = ''.join([chr(byte) if 32 <= byte < 127 else '.' for byte in chunk])
            while len(ascii_chars) < bytes_per_line:
                ascii_chars += ' '
            formatted_line = f"{addr}: {' '.join(hex_values)}  |{ascii_chars}|"
            formatted_output.append(formatted_line)
        return "\n".join(formatted_output)
    except FileNotFoundError:
        return "Error: File not found."
    except IOError as e:
        return f"Error reading file: {e}"
    
def simplify_hex(hex_str):
    try:
        return f"0x{int(hex_str, 16):X}"
    except ValueError:
        return hex_str 
    
def update_hex_preview(window, file_path, offset=0, length=524288):
    try:
        offset_str = window['-ADDRESS-'].get().strip()
        length_str = window['-LENGTH-'].get().strip()
        if not length_str:
            length = 524288
        else:
            length = int(length_str)
        if offset_str.startswith('0x'):
            offset = int(offset_str, 16)
        elif offset_str:
            offset = int(offset_str, 16)
        else:
            offset = 0
        print(f"更新预览: 文件路径={file_path}, 偏移量={offset}, 长度={length}") 
        output = get_hex_dump(file_path, offset, length)
        window['-HEX_PREVIEW_RIGHT-'].update(output or "HEX预览更新失败")
        print("HEX预览已更新" if output else "HEX预览更新失败")
    except ValueError as e:
        window['-HEX_PREVIEW_RIGHT-'].update(f"无效的地址或长度: {e}")
        print(f"无效的地址或长度: {e}")

def extract_addr_and_len_info(line):
    match = re.search(r'(addr\s*=\s*0x[0-9a-fA-F]+),\s*(len\s*=\s*0x[0-9a-fA-F]+)', line, re.IGNORECASE)
    if match:
        addr = simplify_hex(match.group(1).split('=')[1].strip())
        length = simplify_hex(match.group(2).split('=')[1].strip())
        return f"{addr}, {length}"  # 返回简化的匹配字符串
    return None

def extract_device_id(output):
    for line in output.splitlines():
        if 'device id:' in line.lower():
            start_index = line.lower().find('device id:') + len('device id:')
            device_id_part = line[start_index:].split('(')[0].strip()
            if device_id_part:
                return device_id_part
    return None

def extract_nand_model(output):
    for line in output.splitlines():
        if 'nand flash:' in line.lower():
            colon_index = line.lower().find('nand flash:') + len('nand flash:')
            nand_model = line[colon_index:].strip().split(',')[0].strip()
            return nand_model
    return None

def extract_spi_nor_model(output):
    for line in output.splitlines():
        if 'spi nor flash:' in line.lower():
            colon_index = line.lower().find('spi nor flash:') + len('spi nor flash:')
            spi_nor_model = line[colon_index:].strip().split(',')[0].strip()
            return spi_nor_model
    return None

def extract_eeprom_chip(output):
    for line in output.splitlines():
        if 'eeprom chip:' in line.lower():
            colon_index = line.lower().find('eeprom chip:') + len('eeprom chip:')
            eeprom_chip = line[colon_index:].strip().split(',')[0].strip()
            return 'EEPROM Chip  ' + eeprom_chip
    return None

def extract_chip_size(output):
    for line in output.splitlines():
        if 'flash size:' in line.lower():
            colon_index = line.lower().find('flash size:') + len('flash size:')
            chip_size = line[colon_index:].split(',')[0].strip()
            return chip_size
    return None

def extract_oob_size(output):
    for line in output.splitlines():
        if 'oob size:' in line.lower():
            colon_index = line.lower().find('oob size:') + len('oob size:')
            oob_size = line[colon_index:].strip()
            return oob_size
    return None

def extract_ecc_status(output, disable_ecc=False):
    for line in output.splitlines():
        if 'using flash ecc' in line.lower():
            return 'Using Flash ECC'
        elif 'no ecc used' in line.lower():
            return '未使用ECC'
        elif 'disable flash ecc' in line.lower():
            return 'Disable Flash ECC'
    if disable_ecc:
        return '禁用Flash ECC'
    return None

def show_save_file_prompt():
    layout = [
        [sg.Text('请先输入读取保存的文件名')],
        [sg.Column([[sg.Push(), sg.Button('确定'), sg.Push()]], justification='center')]
    ]
    window = sg.Window('提示', layout, size=(200, 70), icon=os.path.join(script_dir, 'SNANDer_x64.ico'), element_justification='center')
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == '确定':
            break
    window.close()

current_process = None
stop_event = threading.Event()

sg.set_options(font=('Microsoft YaHei', 9))
sg.theme('SystemDefault')
env = dict(os.environ, PYTHONUNBUFFERED='1')

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

if getattr(sys, 'frozen', False):
    script_dir = os.path.dirname(sys.executable)
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
background_image_path = resource_path('8pack.png')
image_filename = resource_path('read.png')
image_filename1 = resource_path('write.png')
image_filename2 = resource_path('flash.png')
image_filename3 = resource_path('stop.png')
image_filename4 = resource_path('erase.png')
image_filename6 = resource_path('exit.png')

def get_programmer_exe(programmer):
    """根据选择的编程器返回对应的exe文件路径"""
    exe_map = {
        'CH341A': 'ch341a.exe',
        'CH347T LCV': 'ch347tlcv.exe',
        'CH347T/F': 'SNANDer_x64.exe'
    }
    exe_path = exe_map.get(programmer, 'snander_x64.exe')
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, exe_path)

def get_programmer_menu(selected):
    programmer_items = [
        f"{'✓' if chosen == selected else ' '} {chosen}::select_programmer"
        for chosen in ['CH341A', 'CH347T LCV', 'CH347T/F']
    ]
    return programmer_items

menu_def = [
    ['&File', ['Exit']],
    ['&Programmer', []],
    ['&Help', ['About', 'Flash Support List']]
]

selected_programmer = 'CH347T/F'

def update_menu(window, selected):
    menu_def[1][1] = get_programmer_menu(selected)
    window['Menu'].update(menu_definition=menu_def)

def custom_popup_error(message, icon_path=None):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    layout = [
        [sg.Text(message, text_color='black')],
        [sg.Push(), sg.Button('确定'), sg.Push()]
    ]
    window = sg.Window('错误', layout, icon=icon_path, finalize=True)
    window.bring_to_front()
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == '确定':
            break
    window.close()

def show_flash_support_list():
    layout = [
        [sg.Text('Flash Support List', font=('Microsoft YaHei', 12, 'bold'))],
        [sg.Multiline(size=(60, 30), key='-FLASHTXT-', disabled=True, sbar_trough_color='grey', sbar_background_color=sg.theme_background_color())],
        [sg.Push(), sg.Button('确定'), sg.Push()]
    ]
    window = sg.Window('Flash Support List', layout, icon=resource_path('SNANDer_x64.ico'), finalize=True)
    try:
        with open(resource_path('a.txt'), 'r', encoding='utf-8') as file:
            content = file.read()
        window['-FLASHTXT-'].update(content)
    except FileNotFoundError:
        window['-FLASHTXT-'].update('Error: a.txt not found.')
    
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == '确定':
            break
    window.close()

def custom_popup_disclaimer(icon_path=None):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    disclaimer_message = (
        "本用户界面（UI）是一款独立的应用程序，基于以下开源项目：\n"
        "- https://github.com/McMCCRU/SNANDer\n"
        "- https://github.com/Droid-MAX/SNANDer\n"
        "\n"
        "UI利用Python编写，不会对原程序进行任何修改，UI代码中并不包含上述开源项目中的任何代码，仅\n"
        "调用已编译好的可执行文件与之交互，发出命令与接收输出，旨在简化命令行操作，提供“按现状”的\n"
        "基础功能。用户需自行到上述开源项目网址下载执行程序。\n"
        "\n"
        "开发者不对本UI的功能、性能或适用性作出任何形式的明示或暗示保证。本UI仅供学习与交流使用，不具 \n"
        "有商业用途，完全免费提供。无论在何种情况下，开发者均不对因使用本UI而导致的任何直接、间接、附 \n"
        "带、特殊、惩罚性或后果性的损害承担责任。\n"
        "\n"
        "用户私自更改原程序代码或破坏开源协议，由此产生的后果与本开发者无关。\n"
        "\n"
        "请仔细阅读并理解上述免责声明。一旦确定使用本UI，即表示您已同意并接受上述所有条款。\n"
    )
    layout = [
        [sg.Text('免责声明', justification='center', expand_x=True, font=('Microsoft YaHei', 12, 'bold'))],
        [sg.Text(disclaimer_message, justification='left', text_color='black')],
        [sg.Push(), sg.Button('确定'), sg.Button('拒绝'), sg.Push()]
    ]
    window = sg.Window('免责声明', layout, icon=os.path.join(script_dir, 'SNANDer_x64.ico'), finalize=True)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == '拒绝':
            print("用户拒绝了免责声明，程序将退出。")
            window.close()
            sys.exit()
        elif event == '确定':
            break
    window.close()

layout = [
    [sg.Menu(menu_def, key='Menu')],
    [sg.Column([
        [sg.Frame('', [
            [sg.Button(image_filename=image_filename2, key='-READ_CHIP_ID-', button_color=(sg.theme_background_color(), sg.theme_background_color()), border_width=2, tooltip='获取闪存信息'),
             sg.Button(image_filename=image_filename, key='-READ-', button_color=(sg.theme_background_color(), sg.theme_background_color()), border_width=2, tooltip='读取闪存'),
             sg.Button(image_filename=image_filename1, key='-WRITE-', button_color=(sg.theme_background_color(), sg.theme_background_color()), border_width=2, tooltip='写入闪存'),
             sg.Button(image_filename=image_filename4, key='-ERASE-', button_color=(sg.theme_background_color(), sg.theme_background_color()), border_width=2, tooltip='擦除闪存'),
             sg.Button(image_filename=image_filename3, key='停止', button_color=(sg.theme_background_color(), sg.theme_background_color()), border_width=2, tooltip='停止操作'),
             sg.Button(image_filename=image_filename6, key='退出', button_color=(sg.theme_background_color(), sg.theme_background_color()), border_width=2, tooltip='离开'), sg.Push()
             ]
        ])],
        [sg.Frame('', [
            [sg.Text('保存:', size=(5, 1)), sg.Input(key='-READ_FILENAME-', enable_events=True, size=(15, 1)),
             sg.Text('打开:', size=(5, 1)), sg.Input(key='-FILENAME-', enable_events=True, size=(15, 1), readonly=True),
             sg.FileBrowse(button_color=(sg.theme_background_color(), sg.theme_background_color()), tooltip='打开写入文件'),
             sg.StatusBar('', size=(18, 1), key='-STATUS-')]
        ])],
        [sg.Column([
            [sg.Frame('Flash Info', [
                [sg.Column([
                    [sg.Text('闪存ID:', size=(9, 1)), sg.InputText(key='-DEVICE_ID-', disabled=True, size=(15, 1), justification='center')],
                    [sg.Text('厂商:', size=(9, 1)), sg.InputText(key='-MFR-', disabled=True, size=(15, 1), justification='center')],
                    [sg.Text('型号:', size=(9, 1)), sg.InputText(key='-MODEL-', disabled=True, size=(15, 1), justification='center')],
                    [sg.Text('闪存容量:', size=(9, 1)), sg.InputText(key='-CHIP_SIZE-', disabled=True, size=(15, 1), justification='center')],
                    [sg.Text('OOB Size:', size=(9, 1)), sg.InputText(key='-OOB_SIZE_DISPLAY-', disabled=True, size=(15, 1), justification='center')],
                    [sg.Text('ECC Status:', size=(9, 1)), sg.InputText(key='-ECC_STATUS-', disabled=True, size=(15, 1), justification='center')]
                ])]
            ], expand_x=True, element_justification='left'),
            sg.Column([
                [sg.Column([
                    [sg.Checkbox('关闭ECC', key='-DISABLE_ECC-'), sg.Checkbox('校验', key='-VERIFY-'), sg.Checkbox('忽略坏块', key='-SKIP_BAD_PAGES-'),
                      sg.ProgressBar(100, orientation='h', size=(8, 20), key='-SIMULATED_PROGRESS-', bar_color=('#24f901', 'light gray'))],
                    [sg.Checkbox('忽略ECC错误', key='-IGNORE_ECC-'), sg.Checkbox('8Bit (Microwire EEPROM)', key='-ORG_8BIT-')],
                    [sg.Text('Set add:', size=(6, 1)), sg.Input(key='-ADDRESS-', size=(11, 1)), sg.Text('Set len:', size=(6, 1)), sg.Input(key='-LENGTH-', size=(11, 1))],
                    [sg.Text('set OOB size:'), sg.Input(key='-OOB_SIZE-', size=(3, 1)), sg.Text('选择EEPROM:'), sg.Combo(
                        ['24c01', '24c02', '24c04', '24c08', '24c16', '24c32', '24c64', '24c128', '24c256', '24c512', '24c1024',
                         '93c06', '93c16', '93c46', '93c56', '93c66', '93c76', '93c86', '93c96',
                         '25010', '25020', '25040', '25080', '25160', '25320', '25640', '25128', '25256', '25512', '251024'],
                        key='-EEPROM_TYPE-', button_background_color=sg.theme_background_color(), button_arrow_color='black')],
                    [sg.Text('Set add size (Microwire EEPROM):'), sg.Input(key='-ADDR_LEN-', size=(11, 1))],
                    [sg.Text('Set page size (SPI EEPROM):'), sg.Input(key='-PAGE_SIZE-', size=(16, 1))]
                ], element_justification='left')]
            ], expand_x=True, element_justification='left')
            ]
        ], vertical_alignment='top', element_justification='left')],
        [],
        [sg.Frame('', [
            [sg.Multiline(size=(74, 15), 
                          key='-HEX_PREVIEW-', 
                          disabled=True, 
                          background_color='white',  
                          sbar_trough_color='grey', 
                          sbar_background_color=sg.theme_background_color(),  
                          autoscroll=True, 
                          auto_refresh=True)]
        ], font=('Arial 10 bold'))]
    ], vertical_alignment='top', pad=((0, 10), (0, 0))),
    sg.Column([
        [sg.Frame('Hex Partial Preview', [
            [sg.Multiline(size=(65, 43), key='-HEX_PREVIEW_RIGHT-', disabled=True, font=('Consolas', 10), sbar_trough_color='grey', sbar_background_color=sg.theme_background_color())]
        ], font=('Arial 10 bold'), vertical_alignment='top')],
    ], vertical_alignment='top', pad=((0, 0), (0, 0))) 
]
]

if __name__ == '__main__':
    custom_popup_disclaimer()
    window = sg.Window(
        'SNANDer UI 3.0.6  2025/3/6    8-Pack Abs', layout, icon=resource_path('SNANDer_x64.ico'), size=(1010,600),finalize=True)
    update_menu(window, selected_programmer)


def clean_backspaces(text):
    """清除字符串中的退格字符，并合并覆盖的文本"""
    result = []
    backspace_count = 0
    for char in text:
        if char == '\x08':
            backspace_count += 1
            if result:
                result.pop()
        else:
            if backspace_count > 0:
                result.append('\x08' * backspace_count)
                backspace_count = 0
            result.append(char)
    if backspace_count > 0:
        result.append('\x08' * backspace_count)
    return ''.join(result)

def thread_function(event, values, window):
    global stop_event
    global current_process
    try:
        stop_event.clear() 
        disable_ecc = values.get('-DISABLE_ECC-', False)
        verify = values.get('-VERIFY-', False) 

        current_programmer = selected_programmer
        exe_path = get_programmer_exe(current_programmer)

        if not os.path.exists(exe_path):
            error_message = f"缺少必要的EXE文件: {current_programmer} 所需的 {os.path.basename(exe_path)} 文件不存在。\n请确保该文件与程序在同一目录下。"
            custom_popup_error(error_message, os.path.join(script_dir, 'SNANDer_x64.ico'))

        command = []
        if event == '-READ_CHIP_ID-':
            command = [get_programmer_exe(selected_programmer), '-i']
            operation = '读取芯片ID'
        elif event == '-READ-':
            command = [get_programmer_exe(selected_programmer), '-r', values.get('-READ_FILENAME-', '')]
            operation = '读取'
        elif event == '-ERASE-':
            command = [get_programmer_exe(selected_programmer), '-e']
            operation = '擦除'
        elif event == '-WRITE-':
            command = [get_programmer_exe(selected_programmer), '-w', values.get('-FILENAME-', '')]
            operation = '写入'
        else:
            return
        if values.get('-DISABLE_ECC-'):
            command.append('-d')
        if values.get('-VERIFY-'):
            command.append('-v')
        if values.get('-SKIP_BAD_PAGES-'):
            command.append('-k')
        if values.get('-IGNORE_ECC-'):
            command.append('-I')
        if values.get('-ORG_8BIT-'):
            command.append('-8')

        address = values.get('-ADDRESS-', '')
        length = values.get('-LENGTH-', '')
        eeprom_type = values.get('-EEPROM_TYPE-')
        page_size = values.get('-PAGE_SIZE-', '')
        oob_size = values.get('-OOB_SIZE-', '')
        if address:
            command.extend(['-a', address])
        if length:
            command.extend(['-l', length])
        if eeprom_type:
            command.extend(['-E', eeprom_type])  
        if page_size:
            command.extend(['-s', page_size])
        if oob_size:
            command.extend(['-o', oob_size])

        if (event == '-READ-' or event == '-WRITE-') and (event == '-READ-' and not values['-READ_FILENAME-'] or event == '-WRITE-' and not values['-FILENAME-']):
            window.write_event_value('-SHOW_SAVE_FILE_PROMPT-', None)
            return

        print(f"正在运行命令: {' '.join(command)}")
        command_line = f"{'#' * 50}\n正在执行: {' '.join(command)}\n"
        window['-HEX_PREVIEW-'].print(command_line + '\n', end='') 
        
        if event != '-READ_CHIP_ID-':
            stop_event = threading.Event()
            threading.Thread(target=run_command, args=(command, window, operation, disable_ecc, values), daemon=True).start()
        else:
            threading.Thread(target=run_command, args=(command, window, operation, disable_ecc, values), daemon=True).start()
    except Exception as e:
        print(f"Thread function encountered an error: {e}")
        update_status(window, f"线程函数发生错误: {e}")

def run_command(command, window, operation, disable_ecc, values):
    global stop_event
    global current_process
    try:
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True,
            bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        current_process = process
        output_lines = []
        verification_started = False
        erase_info = None
        read_info = None
        write_info = None
        current_operation = operation
        spi_nor_detected = True
        spi_nand_detected = False
        last_progress_message = "" 
        progress_max = 100 
        simulated_progress = 0 
        simulated_progress_thread = None
        ok_count = 0

        output_line = ''
        device_id = ''
        chip_info = ''
        chip_size = ''
        oob_size = ''
        ecc_status = ''
        mfr = ''
        model = ''
        final_message = ''
        
        window['-SIMULATED_PROGRESS-'].update(current_count=0)
        def simulate_progress():
            nonlocal simulated_progress
            while not stop_event.is_set():
                simulated_progress = (simulated_progress + 1) % (progress_max + 1)
                window.write_event_value('-SIMULATED_PROGRESS-', simulated_progress)
                time.sleep(0.01)
        if operation != '读取芯片ID':
            simulated_progress_thread = threading.Thread(target=simulate_progress, daemon=True)
            simulated_progress_thread.start()

        while True:
            if stop_event.is_set():
                process.terminate()
                break
            char = process.stdout.read(1)
            if not char and process.poll() is not None:
                break
            if char == '\b':
                output_line = output_line[:-1] if len(output_line) > 0 else ''
                continue
            output_line += char
            if char in ('\r', '\n'):
                if output_line.strip():
                    window.write_event_value('-OUTPUT-', output_line.strip())
                if (match := re.search(r'(\d+)%', output_line)):
                    window.write_event_value('-PROGRESS-', int(match.group(1)))
                if "OK" in output_line:
                    ok_count += 1
                if operation == '写入' and values.get('-VERIFY-', False):
                    if ok_count >= 2:
                        stop_event.set()
                else:
                    if ok_count > 0:
                        stop_event.set()
                if operation == '读取芯片ID':
                    device_id = extract_device_id(output_line) or device_id
                    chip_info = extract_nand_model(output_line) or extract_spi_nor_model(output_line) or chip_info
                    chip_size = extract_chip_size(output_line) or chip_size
                    oob_size = extract_oob_size(output_line) or oob_size
                    ecc_status = extract_ecc_status(output_line, disable_ecc) or ecc_status
                    mfr = extract_eeprom_chip(output_line) or mfr
                    model = extract_nand_model(output_line) or extract_spi_nor_model(output_line) or model
        
                    if chip_info:
                        try:
                            mfr, model = chip_info.split(maxsplit=1)
                        except ValueError:
                            mfr, model = '', chip_info 
        
                output_line = ''
        
        for line in iter(process.stdout.readline, ''):
            if not line:
                break
            cleaned_line = clean_backspaces(line.strip())
            output_lines.append(cleaned_line)
            if "Couldn't open CH347 device." in cleaned_line:
                window.write_event_value('-DEVICE_NOT_FOUND-', "未找到设备，请连接或检查驱动")
                break
            if "Couldn't open device 1a86:5512." in cleaned_line:
                window.write_event_value('-DEVICE_NOT_FOUND-', "未找到设备，请连接或检查驱动")
                break
        
        if output_line:
            window.write_event_value('-OUTPUT-', output_line.strip())
        if process.returncode == 0:
            final_message = f""
        else:
            final_message = f""
        if operation == '读取芯片ID':
            window.write_event_value('-THREAD-', (True, output_line, device_id, chip_info, chip_size, oob_size, ecc_status, final_message, mfr, model))
        
        if operation == '读取':
            file_path = values.get('-READ_FILENAME-', '')
            update_hex_preview(window, file_path)
    except Exception as e:
        print(f"Run command encountered an error: {e}")
        update_status(window, f"运行命令时发生错误: {e}")
    finally:
        current_process = None
        window.write_event_value('-PROGRESS-', 100) 
        window['-SIMULATED_PROGRESS-'].update(current_count=0)

def update_status(window, message):
    pass
device_monitor = DeviceMonitor(window)
device_monitor.perform_initial_scan() 

while True:
    event, values = window.read(timeout=100)
    if event in (None, 'Exit','退出'):
        break
    elif event == 'Flash Support List':
            show_flash_support_list()
    if event == '-SHOW_SAVE_FILE_PROMPT-':
        show_save_file_prompt()
    elif event == '-DEVICE_CHANGE-':
        window['-STATUS-'].update(values[event])
    elif event == '-DEVICE_NOT_FOUND-': 
        window.bring_to_front()
        custom_popup_error(values[event], os.path.join(script_dir, 'SNANDer_x64.ico'))

    elif '::select_programmer' in event:
        parts = event.split('::')
        if len(parts) == 2:
            selected_programmer = parts[0].strip()
        new_menu_def = [
            ['&File', ['Exit']],
            ['&Programmer', get_programmer_menu(selected_programmer)],
            ['&Help', ['About']]
        ]
        window['Menu'].update(new_menu_def)
        window['-STATUS-'].update(f"已选择 {selected_programmer} 编程器")

    if event.startswith('select_programmer::'):
        selected_programmer = event.split('::')[0].replace('✓ ', '')
        update_menu(window, selected_programmer)
        window['-CURRENT_PROGRAMMER-'].update(value=f'当前选择的编程器: {selected_programmer}')

    elif event == '-FILENAME-' and values['-FILENAME-']:
        file_path = values['-FILENAME-']
        print(f"选择了文件: {file_path}")
        if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
            update_hex_preview(window, file_path)
        else:
            print(f"文件不可访问或不存在: {file_path}")
            custom_popup_error(f"文件不可访问或不存在: {file_path}", os.path.join(script_dir, 'SNANDer_x64.ico'))
    elif event in ['-ADDRESS-', '-LENGTH-'] and values['-FILENAME-']:
        try:
            offset = int(values['-ADDRESS-'], 16)
            length = int(values['-LENGTH-'])
            file_path = values['-FILENAME-']
            update_hex_preview(window, file_path, offset, length)
        except ValueError:
            window['-HEX_PREVIEW_RIGHT-'].update("请输入有效的地址和长度")

    if event == '提交':
        cmd_args = []
        for key in ['-DISABLE_ECC-', '-IGNORE_ECC-', '-SKIP_BAD_PAGES-', '-VERIFY-', '-ORG_8BIT-']:
            if values[key]:
                if key == '-DISABLE_ECC-':
                    cmd_args.append('-d')
                elif key == '-VERIFY-':
                    cmd_args.append('-v')
                else:
                    flag = '-' + key.replace('-', '').lower() + ('' if len(key) == 3 else ' ')
                    cmd_args.append(flag)

        eeprom_type = values['-EEPROM_TYPE-']
        if eeprom_type:
            cmd_args.append(f'-E {eeprom_type}')
        oob_size = values['-OOB_SIZE-']
        if oob_size:
            cmd_args.append(f'-o {oob_size}')
        addr_len = values['-ADDR_LEN-']
        if addr_len:
            cmd_args.append(f'-f {addr_len}')
        length = values['-LENGTH-']
        if length:
            cmd_args.append(f'-l {length}')
        address = values['-ADDRESS-']
        if address:
            cmd_args.append(f'-a {address}')
        write_file = values['-FILENAME-']
        if write_file:
            cmd_args.append(f'-w {write_file}')
        read_file = values['-READ_FILENAME-']
        if read_file:
            cmd_args.append(f'-r {read_file}')
        exe_path = get_programmer_exe(selected_programmer)
        command_line = f"{exe_path} {' '.join(cmd_args)}"
        sg.popup('生成的命令行:', command_line)

    elif event == '-THREAD-':
        success, output, device_id, chip_info, chip_size, oob_size, ecc_status, final_message, mfr, model = values[event]
        if success:
            window['-DEVICE_ID-'].update(device_id or '')
            window['-MFR-'].update(mfr)
            window['-MODEL-'].update(model)
            window['-CHIP_SIZE-'].update(chip_size or '')
            window['-OOB_SIZE_DISPLAY-'].update(oob_size or '')
            window['-ECC_STATUS-'].update(ecc_status or '')
            update_status(window, final_message)
            window['-SIMULATED_PROGRESS-'].update(current_count=0)

    elif event == 'About':
        about_layout = [
            [sg.Image(filename=background_image_path, key='-BACKGROUND-')],
            [sg.Text('本程序仅为SNANDer提供用户界面，请到下面网址下载原程序配合使用。')],
            [sg.Text('https://github.com/McMCCRU/SNANDer'), sg.Push(), sg.Text('https://github.com/Droid-MAX/SNANDer')],
            [sg.Text('CH341程序请把程序SNANDer_x64.exe改为ch341a.exe，CH347程序不需要更改。')],
            [sg.Text('把原程序和与本程序在同一目录下方能调用交互。')],
            [sg.Text('Copyright © 2025 8-Pack Abs. All rights reserved.')],
            [sg.Button('确定')]
        ]
        about_window = sg.Window('About SNANDer UI', about_layout, icon=resource_path('SNANDer_x64.ico'), element_justification='center')
        while True:
            event, values = about_window.read()
            if event in (sg.WIN_CLOSED, '确定'):
                about_window.close()
                break

    if event in ['-READ_CHIP_ID-', '-READ-', '-WRITE-', '-ERASE-']:
        thread_function(event, values, window)
    if event == '-OUTPUT-':
        output_line = values['-OUTPUT-']
        if 'SNANDer - Serial Nor/nAND/Eeprom programmeR v.1.7.8 by McMCC <mcmcc@mail.ru>' in output_line:
            continue
        formatted_line = output_line.replace('\b', '')
        if any(keyword in formatted_line for keyword in ["Detected", "Status:"]):
            formatted_line = f"★ {formatted_line.strip()}\n"
        elif any(keyword in formatted_line for keyword in ["Erase", "Write", "Verify"]):
            formatted_line = f"▶ {formatted_line.strip()}\n"
        else:
            formatted_line = f"  {formatted_line.strip()}\n"
        window['-HEX_PREVIEW-'].print(formatted_line, end='')
        
        #window.refresh() 
        # 不再通过 '-OUTPUT-' 更新状态栏

    elif event == '-SIMULATED_PROGRESS-':
        progress_value = values[event]
        window['-SIMULATED_PROGRESS-'].update(current_count=progress_value)
        window.refresh() 

    elif event == '停止':
        stop_event.set() 
        if current_process:
            current_process.terminate() 
            window['-HEX_PREVIEW-'].print("\n操作已终止。\n", end='')

window.close()