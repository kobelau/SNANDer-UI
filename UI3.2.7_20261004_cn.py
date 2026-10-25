import PySimpleGUI as sg
import os
import sys
import threading
import subprocess
import re
import ctypes
import time
import uuid
import configparser
import queue
import hashlib
import math

        
setupapi = ctypes.windll.LoadLibrary("SetupAPI.dll")

DIGCF_PRESENT = 0x00000002
DIGCF_DEVICEINTERFACE = 0x00000010
INVALID_HANDLE_VALUE = -1
SPDRP_DEVICEDESC = 0x00000000

TARGET_VID_PIDS = {
    'VID_1A86&PID_55DB': 'CH347T',
    'VID_1A86&PID_55DE': 'CH347F',
    'VID_1A86&PID_5512': 'CH341A',
}

                    
DEVICE_TO_PROGRAMMER = {
    'CH341A': 'CH341A',
    'CH347T': 'CH347T/F',
    'CH347F': 'CH347T/F',
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
        try:
            if self.window is None or self.window.was_closed():
                return
            self.window.write_event_value('-DEVICE_CHANGE-', message)
        except Exception:
            pass

    def build_status(self, devices):
        if not devices:
            return '未检测到设备'
        names = []
        for device_id, (name, description) in devices.items():
            if name and name not in names:
                names.append(name)
        if not names:
            return '未检测到设备'
        text = '、'.join(names) + ' 已连接'
        if len(text) > 16:                         
            text = f'{len(names)} 个设备已连接'
        return text

    def report(self, devices):
        self.update_status_bar(self.build_status(devices))
                                                       
        names = {v[0] for v in devices.values()}
        programmer = None
        for name in ('CH347T', 'CH347F', 'CH341A'):
            if name in names:
                programmer = DEVICE_TO_PROGRAMMER[name]
                break
        if programmer:
            try:
                self.window.write_event_value('-AUTO_SELECT_PROGRAMMER-', programmer)
            except Exception:
                pass

    def monitor_device_changes(self):
        self.perform_initial_scan()
        while True:
            time.sleep(2)
                                      
            if self.window is None or self.window.was_closed():
                return
            try:
                current_devices = get_connected_devices()
                                          
                if current_devices != self.previous_devices:
                    self.previous_devices = current_devices.copy()
                    self.report(current_devices)
            except Exception as e:
                self.update_status_bar(f"An error occurred: {e}")

    def perform_initial_scan(self):
        try:
            initial_devices = get_connected_devices()
            self.previous_devices = initial_devices.copy()
            self.report(initial_devices)
        except Exception as e:
            self.update_status_bar(f"An error occurred during initial scan: {e}")

class BadBlockMap:
    def __init__(self, window):
        self.window = window
        self.graph = window['-BADBLOCK_MAP-']
        self.total_blocks = 0
        self.block_size = 128 * 1024           
        self.bad_blocks = set()
        self.skip_blocks = set()
        self.blocks_per_cell = 1                          
        self.display_blocks = 0             
        
    def init_chip(self, flash_size_str, block_size_kb=None):
        if flash_size_str == "Flash Not Detected" or not flash_size_str:
                   
            self.window['-TOTAL_BLOCKS-'].update("未检测")
            self.window['-MAP_CHIP_SIZE-'].update("--")
            self.show_no_chip()
            return
        try:
                                             
            size_str = str(flash_size_str).upper().replace(' ', '').replace(',', '')
            match = re.search(r'(\d+(?:\.\d+)?)\s*(MB|GB|G|M)?', size_str)
            if match:
                num = float(match.group(1))
                unit = match.group(2) if match.group(2) else 'MB'
                if unit.startswith('G'):
                    total_bytes = int(num * 1024 * 1024 * 1024)
                else:
                    total_bytes = int(num * 1024 * 1024)
            else:
                total_bytes = 128 * 1024 * 1024

                                   
            if block_size_kb:
                self.block_size = int(block_size_kb) * 1024
            else:
                              
                if total_bytes >= 1024*1024*1024:                         
                    self.block_size = 256 * 1024
                elif total_bytes >= 512*1024*1024:                  
                    self.block_size = 256 * 1024
                else:
                    self.block_size = 128 * 1024             

            self.total_blocks = total_bytes // self.block_size
            
                                                            
                                     
            max_cells = 256
            if self.total_blocks <= max_cells:
                self.blocks_per_cell = 1
                self.display_blocks = self.total_blocks
            else:
                               
                self.blocks_per_cell = (self.total_blocks + max_cells - 1) // max_cells
                self.display_blocks = (self.total_blocks + self.blocks_per_cell - 1) // self.blocks_per_cell
            
                                      
            self.cols = min(32, self.display_blocks)
            self.rows = math.ceil(self.display_blocks / self.cols)
            
            self.bad_blocks.clear()
            self.skip_blocks.clear()
            self.draw()
            
                    
            compression_info = f"(1格={self.blocks_per_cell}块)" if self.blocks_per_cell > 1 else ""
            self.window['-BADBLOCK_FRAME-'].update(visible=True)
            self.window['-TOTAL_BLOCKS-'].update(f"{self.total_blocks} {compression_info}")
            self.window['-MAP_CHIP_SIZE-'].update(flash_size_str)
            self.update_counts()
            
        except Exception as e:
            print(f"BadBlockMap init error: {e}")
            import traceback
            traceback.print_exc()

    def add_bad_block(self, block_idx):
        try:
            idx = int(block_idx)
            if 0 <= idx < self.total_blocks:
                self.bad_blocks.add(idx)
                self.draw()
                self.update_counts()
        except:
            pass
            
    def add_skip_block(self, block_idx):
        try:
            idx = int(block_idx)
            if 0 <= idx < self.total_blocks:
                self.skip_blocks.add(idx)
                self.draw()
                self.update_counts()
        except:
            pass
            
    def parse_line(self, line):
        line_lower = line.lower()
        found = False
        
               
                                               
                                   
                                    
                                    
        
        patterns = [
            (r'bad\s*block.*?0x([0-9a-fA-F]+)', 'addr'),            
            (r'bad\s*block[:\s@]*(\d+)', 'blk'),                    
            (r'bb[:\s]*(\d+)', 'blk'),                                    
            (r'skipping\s*block[:\s]*(\d+)', 'skip'),             
            (r'skip.*?block[:\s]*(\d+)', 'skip'),                   
            (r'block[:\s]*(\d+)\s*(?:is\s*)?bad', 'blk'),                       
        ]
        
        for pattern, typ in patterns:
            match = re.search(pattern, line_lower)
            if match:
                if typ == 'addr':
                    addr = int(match.group(1), 16)
                    block_idx = addr // self.block_size
                else:
                    block_idx = int(match.group(1))
                
                if typ == 'skip':
                    self.add_skip_block(block_idx)
                else:
                    self.add_bad_block(block_idx)
                found = True
                break
                
        return found
        
    def update_counts(self):
        try:
            self.window['-BAD_COUNT-'].update(str(len(self.bad_blocks)))
            self.window['-SKIP_COUNT-'].update(str(len(self.skip_blocks)))
        except:
            pass
        
    def draw(self):
        try:
            self.graph.erase()
            
            if self.total_blocks == 0:
                return
            
                                                            
            canvas_w, canvas_h = self.graph.CanvasSize
            margin = 5
            
                         
            usable_w = canvas_w - 2*margin
            usable_h = canvas_h - 2*margin
            cell_w = usable_w / self.cols
            cell_h = usable_h / self.rows
            cell_size = min(cell_w, cell_h) * 0.85       
            
            for display_idx in range(self.display_blocks):
                row = display_idx // self.cols
                col = display_idx % self.cols
                
                                
                start_block = display_idx * self.blocks_per_cell
                end_block = min(start_block + self.blocks_per_cell, self.total_blocks)
                
                                
                has_bad = any(b in self.bad_blocks for b in range(start_block, end_block))
                has_skip = any(b in self.skip_blocks for b in range(start_block, end_block))
                
                                           
                if has_bad:
                    color = 'red'
                    border = 'darkred'
                elif has_skip:
                    color = 'orange'
                    border = 'darkorange'
                else:
                    color = '#90EE90'      
                    border = 'gray'
                
                                               
                x = margin + col * cell_w + cell_w/2
                y = canvas_h - margin - row * cell_h - cell_h/2        
                
                half = cell_size / 2
                self.graph.draw_rectangle(
                    (x - half, y - half),
                    (x + half, y + half),
                    fill_color=color,
                    line_color=border,
                    line_width=1 if not has_bad else 2          
                )
                
                                 
                if has_bad and cell_size > 10 and self.blocks_per_cell <= 4:
                    self.graph.draw_text('B', (x, y), color='white', font=('Arial', 8, 'bold'))
                elif has_bad and cell_size > 6:
                    self.graph.draw_text('·', (x, y), color='white', font=('Arial', 12))
                    
        except Exception as e:
            print(f"Draw error: {e}")
            
    def clear(self):
        self.bad_blocks.clear()
        self.skip_blocks.clear()
        self.draw()
        self.update_counts()

    def show_no_chip(self):
        self.graph.erase()
        self.total_blocks = 0
        self.display_blocks = 0
        
                
        self.window['-TOTAL_BLOCKS-'].update("未检测")
        self.window['-MAP_CHIP_SIZE-'].update("--")
        self.window['-BAD_COUNT-'].update("0")
        self.window['-SKIP_COUNT-'].update("0")
        
                                         
        cw, ch = self.graph.CanvasSize
        self.graph.draw_text(
            '未检测到芯片',
            (cw // 2, ch * 0.58),          
            font=('Microsoft YaHei', 14),
            color='gray',
            text_location='center'
        )
        self.graph.draw_text(
            '请先点击"获取闪存信息"按钮',
            (cw // 2, ch * 0.38),
            font=('Microsoft YaHei', 9),
            color='lightgray',
            text_location='center'
        )

                    
        self.graph.draw_rectangle(
            (cw * 0.125, ch * 0.25), (cw * 0.875, ch * 0.75),
            fill_color=None,
            line_color='lightgray',
            line_width=1
        )

                                                
                               
MAX_HEX_PREVIEW_LINES = 2000

                                       
                                                          
HEX_LINE_CHARS = 53

def get_hex_dump(file_path, offset=0, length=524288):
    try:
        bytes_per_line = 10
                                                  
        read_length = min(length, (MAX_HEX_PREVIEW_LINES + 1) * bytes_per_line)
        with open(file_path, 'rb') as f:
            f.seek(offset)
            data = f.read(read_length)
        byte_width = 2
        space_between_bytes = 1
        total_byte_width = bytes_per_line * (byte_width + space_between_bytes) - space_between_bytes
        ascii_width = bytes_per_line
        hex_header = ' '.join(f'{i:02X}' for i in range(bytes_per_line))
        header = f"Address: {hex_header}    ASCII"
        separator = "--------+" + "-" * total_byte_width + "+" + "-" * ascii_width
        formatted_output = [header, separator]
        total_lines = (len(data) + bytes_per_line - 1) // bytes_per_line
        for line_num, i in enumerate(range(0, len(data), bytes_per_line)):
            if line_num >= MAX_HEX_PREVIEW_LINES:
                formatted_output.append(f"... (仅预览前 {MAX_HEX_PREVIEW_LINES} 行，超出部分未加载)")
                break
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
        return f"{addr}, {length}"
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
    window = sg.Window('提示', layout, size=(200, 70), icon=resource_path('SNANDer_x64.ico'), element_justification='center')
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == '确定':
            break
    window.close()

current_process = None
current_operation = None
current_phase = 'main'
stop_event = threading.Event()
user_stop_event = threading.Event()
progress_queue = queue.Queue()

                                   
                               
UI_FONT = ('Microsoft YaHei', 9)
UI_FONT_FALLBACK_CHAR_PX = 8                                             

                                        
                                               
HEX_PREVIEW_FONT = 'Consolas'
HEX_PREVIEW_BASE_SIZE = 10

sg.set_options(font=UI_FONT)
sg.theme('SystemDefault')


def ui_char_px():
    try:
        import tkinter.font as tkfont
        px = tkfont.Font(family=UI_FONT[0], size=UI_FONT[1]).measure('A')
        return px if px > 0 else UI_FONT_FALLBACK_CHAR_PX
    except Exception:
        return UI_FONT_FALLBACK_CHAR_PX


def progressbar_px(chars):
    return int(round(chars * ui_char_px()))
env = dict(os.environ, PYTHONUNBUFFERED='1')

def resource_path(relative_path):
    try:
                            
        base_path = sys._MEIPASS
    except Exception:
                                  
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

background_image_path = resource_path('8pack.png')
image_filename = resource_path('read.png')
image_filename1 = resource_path('write.png')
image_filename2 = resource_path('flash.png')
image_filename3 = resource_path('stop.png')
image_filename4 = resource_path('erase.png')
image_filename6 = resource_path('exit.png')

def get_programmer_exe(programmer):
    exe_map = {
        'CH341A': 'ch341a.exe',
        'CH347T/F': 'SNANDer_x64.exe'
    }
    exe_path = exe_map.get(programmer, 'SNANDer_x64.exe')
    
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    
    user_exe_path = os.path.join(os.path.dirname(sys.executable), exe_path)
    if os.path.exists(user_exe_path):
        full_path = user_exe_path
    else:
        full_path = os.path.join(base_path, exe_path)
    
    return full_path

def get_programmer_menu(selected):
    programmers = ['CH341A', 'CH347T/F']
    
    programmer_items = []
    for programmer in programmers:
        if programmer == selected:
            programmer_items.append(f"✓ {programmer}::select_programmer")
        else:
            programmer_items.append(f"{programmer}::select_programmer")
    
    return programmer_items

SPI_SPEEDS = ['60M', '30M', '15M', '10M', '5M', '2M']
selected_spi_speed = '60M'
selected_programmer = 'CH341A'
def get_speed_menu(selected_speed):
    speed_items = [
        f"{'✓' if s == selected_speed else ' '} {s}::select_speed"
        for s in SPI_SPEEDS
    ]
    return speed_items

menu_def = [
    ['&File', ['Exit']],
    ['&Tools', ['Firmware Compare']],
    ['&Programmer', get_programmer_menu('CH341A')],
    ['SPI频率', get_speed_menu('60M')],
    ['&Help', ['About', 'Flash Support List']]
]

def update_menu(window, selected):
    new_menu_def = [
        ['&File', ['Exit']],
        ['&Tools', ['Firmware Compare']],
        ['&Programmer', get_programmer_menu(selected)],
        ['SPI频率', get_speed_menu(selected_spi_speed) if selected == 'CH347T/F' else ['（仅CH347T/F支持）']],
        ['&Help', ['About', 'Flash Support List']]
    ]
    window['Menu'].update(menu_definition=new_menu_def)

def custom_popup_error(message, icon_path=None):
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
    disclaimer_message = (
        "本用户界面（UI）是一款独立的应用程序，基于以下开源项目：\n"
        "- https://github.com/McMCCRU/SNANDer\n"
        "- https://github.com/Droid-MAX/SNANDer\n"
        "\n"
        "UI利用Python编写，不会对原程序进行任何修改，UI代码中并不包含上述开源项目中的任何代码，仅\n"
        "调用已编译好的可执行文件与之交互，发出命令与接收输出，旨在简化命令行操作，提供按现状的\n"
        "基础功能。用户需自行到上述开源项目网址下载执行程序。\n"
        "\n"
        "开发者不对本UI的功能、性能或适用性作出任何形式的明示或暗示保证。本UI仅供学习与交流使用，不具 \n"
        "有商业用途，完全免费提供。无论在何种情况下，开发者均不对因使用本UI而导致的任何直接、间接、附 \n"
        "带、特殊、惩罚性或后果性的损害承担责任。\n"
        "\n"
        "用户私自更改原程序代码或破坏开源协议，由此产生的后果与本开发者无关。\n"
        "\n"
        "请仔细阅读并理解上述免责声明。一旦确定使用本UI，即表示您已同意并接受上述所有条款。\n"
        "\n"
        "Development Environment: Win10, VSCode, Python 3.13\n"
    )
    layout = [
        [sg.Text('免责声明', justification='center', font=('Microsoft YaHei', 12, 'bold'))],
        [sg.Text(disclaimer_message, justification='left', text_color='black')],
        [sg.Push(), sg.Button('确定'), sg.Button('拒绝'), sg.Push()]
    ]
    window = sg.Window('免责声明', layout, icon=resource_path('SNANDer_x64.ico'), finalize=True)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == '拒绝':
            print("用户拒绝了免责声明，程序将退出。")
            window.close()
            sys.exit()
        elif event == '确定':
            break
    window.close()

def get_settings_path():
    try:
        if getattr(sys, 'frozen', False):
            base = os.path.dirname(sys.executable)
        else:
            base = os.path.dirname(os.path.abspath(__file__))
    except Exception:
        base = os.getcwd()
    if not os.path.isdir(base) or not os.access(base, os.W_OK):
        appdata = os.environ.get('APPDATA') or os.path.expanduser('~')
        base = os.path.join(appdata, 'SNANDerUI')
        try:
            os.makedirs(base, exist_ok=True)
        except Exception:
            pass
    return os.path.join(base, 'settings.ini')

def save_programmer_choice(programmer):
    config = configparser.ConfigParser()
    config['Settings'] = {'selected_programmer': programmer}
    try:
        with open(get_settings_path(), 'w', encoding='utf-8') as configfile:
            config.write(configfile)
    except Exception as e:
        print(f"保存配置失败（不影响使用）: {e}")

def load_programmer_choice():
    config = configparser.ConfigParser()
    try:
        config.read(get_settings_path(), encoding='utf-8')
        value = config.get('Settings', 'selected_programmer', fallback='CH341A').strip()
                                        
        return value if value in ('CH341A', 'CH347T/F') else 'CH341A'
    except Exception:
        return 'CH341A'

def show_firmware_compare(main_window):
    layout = [
        [sg.Text('原始文件 (旧版本):', size=(15, 1)), 
         sg.Input(key='-FILE1-', size=(35, 1)), 
         sg.FileBrowse(button_color=(sg.theme_background_color(), sg.theme_background_color()))],
        [sg.Text('目标文件 (新版本):', size=(15, 1)), 
         sg.Input(key='-FILE2-', size=(35, 1)), 
         sg.FileBrowse(button_color=(sg.theme_background_color(), sg.theme_background_color()))],
        [sg.Frame('对比模式', [
            [sg.Radio('智能对比 (先哈希后详细)', 'MODE', default=True, key='-SMART-'),
             sg.Radio('仅哈希对比 (最快)', 'MODE', default=False, key='-HASH-'),
             sg.Radio('详细逐字节 (最慢)', 'MODE', default=False, key='-DETAIL-')]
        ])],
                                                        
        [sg.ProgressBar(100, orientation='h', size_px=(440, 20), key='-PROGRESS-', 
                       bar_color=('#24f901', 'light gray'))],
                          
        [sg.Frame('', [
            [sg.Multiline(size=(60, 12), 
                          key='-RESULT-', 
                          disabled=True, 
                          autoscroll=True,
                          background_color='white',
                          sbar_trough_color='#d3d3d3',               
                          sbar_background_color='#a9a9a9',          
                          sbar_arrow_color='#696969',             
                          pad=(2, 2))]
        ], background_color='#a9a9a9', pad=(0, 0), relief='solid', border_width=1)],
        
        [sg.Push(), 
         sg.Button('开始对比', key='-START-', button_color=('black', 'light gray')), 
         sg.Button('关闭', button_color=('black', 'light gray')), 
         sg.Push()]
    ]
    
    cmp_window = sg.Window('固件对比工具', layout,
                          icon=resource_path('SNANDer_x64.ico'),
                          modal=True, finalize=True)

                            
    fix_progressbar_length(cmp_window['-PROGRESS-'], progressbar_px(55))
    
    comparing = False
    cmp_queue = None
    
    while True:
        event, values = cmp_window.read(timeout=100)
        
        if event in (sg.WIN_CLOSED, '关闭'):
            break
            
        elif event == '-START-' and not comparing:
            file1 = values['-FILE1-']
            file2 = values['-FILE2-']
            
            if not file1 or not file2:
                sg.popup_error('请选择两个文件！', icon=resource_path('SNANDer_x64.ico'))
                continue
                
            if not os.path.exists(file1) or not os.path.exists(file2):
                sg.popup_error('文件不存在！', icon=resource_path('SNANDer_x64.ico'))
                continue
            
            if file1 == file2:
                sg.popup_error('不能选择同一个文件！', icon=resource_path('SNANDer_x64.ico'))
                continue
            
            cmp_window['-RESULT-'].update('')
            cmp_window['-START-'].update(disabled=True)
            comparing = True
            
            if values['-HASH-']:
                mode = 'hash'
            elif values['-DETAIL-']:
                mode = 'detail'
            else:
                mode = 'smart'
            
            cmp_queue = queue.Queue()
            
            def compare_worker(f1, f2, mode, q):
                try:
                    size1 = os.path.getsize(f1)
                    size2 = os.path.getsize(f2)
                    
                    q.put(('log', f"文件1: {os.path.basename(f1)} ({size1/1024/1024:.2f} MB)"))
                    q.put(('log', f"文件2: {os.path.basename(f2)} ({size2/1024/1024:.2f} MB)"))
                    
                    if size1 != size2:
                        q.put(('log', f"⚠️ 文件大小不同！"))
                        q.put(('done', None))
                        return
                    
                    if mode in ['smart', 'hash']:
                        q.put(('log', "计算文件哈希..."))

                        def md5_file(path, progress_from, progress_to):
                            h = hashlib.md5()
                            total = max(os.path.getsize(path), 1)
                            done = 0
                            last_pct = -1
                            with open(path, 'rb') as fp:
                                while True:
                                    chunk = fp.read(4 * 1024 * 1024)
                                    if not chunk:
                                        break
                                    h.update(chunk)
                                    done += len(chunk)
                                    pct = progress_from + int(done / total * (progress_to - progress_from))
                                    if pct != last_pct:
                                        last_pct = pct
                                        q.put(('progress', pct))
                            return h.hexdigest()

                        md5_1 = md5_file(f1, 0, 50)
                        md5_2 = md5_file(f2, 50, 100)
                        
                        q.put(('log', f"文件1 MD5: {md5_1}"))
                        q.put(('log', f"文件2 MD5: {md5_2}"))
                        
                        if md5_1 == md5_2:
                            q.put(('log', "✅ 文件完全相同！"))
                            q.put(('done', None))
                            return
                        else:
                            q.put(('log', "⚠️ 哈希不同，存在差异"))
                            if mode == 'hash':
                                q.put(('done', None))
                                return
                    
                    q.put(('log', "开始详细逐字节对比..."))
                    block_size = 1024 * 1024
                    total_blocks = (size1 + block_size - 1) // block_size
                    diff_count = 0
                    
                    with open(f1, 'rb') as fp1, open(f2, 'rb') as fp2:
                        for i in range(total_blocks):
                            chunk1 = fp1.read(block_size)
                            chunk2 = fp2.read(block_size)
                            
                            if chunk1 != chunk2:
                                for j, (b1, b2) in enumerate(zip(chunk1, chunk2)):
                                    if b1 != b2:
                                        addr = i * block_size + j
                                        q.put(('log', f"差异 @ 0x{addr:08X}: 0x{b1:02X} ≠ 0x{b2:02X}"))
                                        diff_count += 1
                                        if diff_count >= 10:
                                            q.put(('log', "... (差异过多，省略)"))
                                            break
                                if diff_count >= 10:
                                    break
                            
                            progress = int((i + 1) / total_blocks * 100)
                            if i % 5 == 0:
                                q.put(('progress', progress))
                    
                    q.put(('log', f"对比完成，共发现 {diff_count} 处差异"))
                    q.put(('done', None))
                    
                except Exception as e:
                    q.put(('log', f"错误: {str(e)}"))
                    q.put(('done', None))
            
            threading.Thread(target=compare_worker, 
                           args=(file1, file2, mode, cmp_queue), 
                           daemon=True).start()
        
                
        if comparing and cmp_queue:
            try:
                while True:
                    msg_type, msg_data = cmp_queue.get_nowait()
                    
                    if msg_type == 'log':
                        current = cmp_window['-RESULT-'].get()
                        cmp_window['-RESULT-'].update(current + msg_data + '\n')
                    elif msg_type == 'progress':
                        cmp_window['-PROGRESS-'].update(current_count=msg_data)
                    elif msg_type == 'done':
                        cmp_window['-START-'].update(disabled=False)
                        cmp_window['-PROGRESS-'].update(current_count=100)
                        comparing = False
                        break
            except queue.Empty:
                pass
    
    cmp_window.close()

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
             sg.StatusBar('', size=(17, 1), key='-STATUS-')]
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
            ], element_justification='left'),
            sg.Column([
                [sg.Column([
                    [sg.Checkbox('关闭ECC', key='-DISABLE_ECC-'), sg.Checkbox('校验', key='-VERIFY-'), sg.Checkbox('忽略坏块', key='-SKIP_BAD_PAGES-')],
                    [sg.Checkbox('忽略ECC错误', key='-IGNORE_ECC-'), sg.Checkbox('8Bit (Microwire EEPROM)', key='-ORG_8BIT-')],
                    [sg.Text('Set add:', size=(6, 1)), sg.Input(key='-ADDRESS-', size=(11, 1)), sg.Text('Set len:', size=(6, 1)), sg.Input(key='-LENGTH-', size=(11, 1))],
                    [sg.Text('set OOB size:'), sg.Input(key='-OOB_SIZE-', size=(3, 1)), sg.Text('选择EEPROM:'), sg.Combo(
                        ['24c01', '24c02', '24c04', '24c08', '24c16', '24c32', '24c64', '24c128', '24c256', '24c512', '24c1024',
                         '93c06', '93c16', '93c46', '93c56', '93c66', '93c76', '93c86', '93c96',
                         '25010', '25020', '25040', '25080', '25160', '25320', '25640', '25128', '25256', '25512', '251024'],
                        key='-EEPROM_TYPE-', button_background_color=sg.theme_background_color(), button_arrow_color='black')],
                    [sg.Text('Set add size (Microwire EEPROM):'), sg.Input(key='-ADDR_LEN-', size=(11, 1))],
                    [sg.Text('Set page size (SPI EEPROM):'), sg.Input(key='-PAGE_SIZE-', size=(16, 1))],
                                                                    
                                                          
                                                                       
                    [sg.ProgressBar(100, orientation='h', size_px=(248, 14), key='-REAL_PROGRESS-', bar_color=('#24f901', 'light gray')),
 sg.Text('0%', key='-PROGRESS_PCT-', size=(5,1), justification='center')]
                ], element_justification='left')]
            ], element_justification='left')
            ]
        ], vertical_alignment='top', element_justification='left')],

        [sg.Frame('', [
            [sg.Multiline(size=(73, 19),
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
            [sg.Multiline(size=(61, 28), key='-HEX_PREVIEW_RIGHT-', disabled=True, font=(HEX_PREVIEW_FONT, HEX_PREVIEW_BASE_SIZE), sbar_trough_color='grey', sbar_background_color=sg.theme_background_color())]
        ], font=('Arial 10 bold'), vertical_alignment='top', key='-HEX_FRAME_RIGHT-')],
        
        [sg.Frame('Bad Block Map (NAND)', [
            [sg.Graph(
                canvas_size=(448, 120),
                graph_bottom_left=(0, 0),
                graph_top_right=(448, 120),
                key='-BADBLOCK_MAP-',
                background_color='white',
                tooltip='绿色=正常, 红色=坏块, 橙色=已跳过'
            )],
            [sg.Column([
                [sg.Text('总块数:', size=(6, 1)),
                 sg.Text('--', key='-TOTAL_BLOCKS-', size=(10, 1), relief='sunken'),
                 sg.Text('坏块数:', size=(6, 1)),
                 sg.Text('0', key='-BAD_COUNT-', size=(4, 1), relief='sunken', text_color='red'),
                 sg.Text('已跳过:', size=(6, 1)),
                 sg.Text('0', key='-SKIP_COUNT-', size=(4, 1), relief='sunken', text_color='orange'),
                 sg.Text('容量:', size=(4, 1)),
                 sg.Text('--', key='-MAP_CHIP_SIZE-', size=(8, 1), relief='sunken')]
            ])],
            [sg.Text('图例:', font=('Arial', 8), size=(6,1)),
             sg.Text('■', text_color='#90EE90', font=('Arial', 10)), sg.Text('正常', font=('Arial', 8)),
             sg.Text('■', text_color='red', font=('Arial', 10)), sg.Text('坏块', font=('Arial', 8)),
             sg.Text('■', text_color='orange', font=('Arial', 10)), sg.Text('已跳过', font=('Arial', 8))]
        ], font=('Arial 10 bold'), key='-BADBLOCK_FRAME-')]              
    ], vertical_alignment='top', pad=((0, 0), (0, 0)))
]
]


def thread_function(event, values, window):
    global stop_event, user_stop_event, current_process, current_operation, current_phase
    try:
        stop_event.clear()
        user_stop_event.clear()
        progress_queue.queue.clear()
        
        disable_ecc = values.get('-DISABLE_ECC-', False)
        verify = values.get('-VERIFY-', False)        

        current_programmer = selected_programmer
        try:
            exe_path = get_programmer_exe(current_programmer)
        except FileNotFoundError:
            error_message = "缺少必要的EXE文件: 所需的 SNANDer_x64.exe 文件不存在。\n请确保该文件与程序在同一目录下。"
            custom_popup_error(error_message, resource_path('SNANDer_x64.ico'))
            return

        if not os.path.exists(exe_path):
            error_message = f"缺少必要的EXE文件: 所需的 {os.path.basename(exe_path)} 文件不存在。\n请确保该文件与程序在同一目录下。"
            custom_popup_error(error_message, resource_path('SNANDer_x64.ico'))
            return

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
        
        current_operation = operation
        current_phase = 'main'

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
        if selected_programmer == 'CH347T/F':
            command.extend(['-S', selected_spi_speed])

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
        command_line = f"{'#' * 50}\nExecuting, please wait......"
        window['-HEX_PREVIEW-'].print(command_line + '\n', end='')
        
        threading.Thread(target=run_command, args=(command, window, operation, disable_ecc, values), daemon=True).start()
    except Exception as e:
        print(f"Thread function encountered an error: {e}")
        update_status(window, f"线程函数发生错误: {e}")

def run_command(command, window, operation, disable_ecc, values):
    global stop_event, current_process, current_operation, current_phase
    current_operation = operation
    current_phase = 'main'
    process = None                                      

    try:        
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            errors='replace',                            
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
            startupinfo=startupinfo
        )
        current_process = process
                
        output_line = ''
        last_progress = -1
        ok_count = 0
        failed = False                                   
        captured_lines = []                                          
        
                    
        device_id = chip_info = chip_size = oob_size = ecc_status = mfr = model = ''
        
        window.write_event_value('-PROGRESS_EVENT-', 0)
        
        while True:
            if stop_event.is_set():                
                break
                
            char = process.stdout.read(1)
            if not char and process.poll() is not None:
                break
                
            if char == '\b':
                if output_line:
                    output_line = output_line[:-1]
                continue
                
            output_line += char
            
                 
            if char in ('\r', '\n'):
                line = output_line.strip()
                output_line = ''
                
                if not line:
                    continue
                
                         
                window.write_event_value('-OUTPUT-', line)
                if line == 'VERIFY:':
                    current_phase = 'verify'
                    print(f"[DEBUG] 检测到 VERIFY: 标记，切换到验证阶段")
                
                         
                match = re.search(r'(Erase|Written|Read|Verify|Verifying)\s+(\d+)%', line, re.IGNORECASE)
                if match:
                    pct = int(match.group(2))
                    action = match.group(1).lower()
                             
                    if 'verify' in action:
                        current_phase = 'verify'
                    if pct != last_progress:
                        last_progress = pct
                        window.write_event_value('-PROGRESS_EVENT-', pct)
                
                        
                if 'Status: OK' in line or 'Verify OK' in line:
                    ok_count += 1
                    if operation == '写入' and values.get('-VERIFY-', False):
                        if ok_count >= 2:
                            stop_event.set()
                    else:
                        if ok_count >= 1:
                            stop_event.set()
                
                                                       
                                  
                if 'Status: BAD' in line or re.search(r'\bFAIL(?:ED)?\b', line):
                    failed = True
                    stop_event.set()
                
                             
                if operation == '读取芯片ID':
                    captured_lines.append(line)
                    device_id = extract_device_id(line) or device_id
                    chip_info = extract_nand_model(line) or extract_spi_nor_model(line) or chip_info
                    chip_size = extract_chip_size(line) or chip_size
                    oob_size = extract_oob_size(line) or oob_size
                    ecc_status = extract_ecc_status(line, disable_ecc) or ecc_status
                    mfr = extract_eeprom_chip(line) or mfr
                    model = extract_nand_model(line) or extract_spi_nor_model(line) or model
                    if chip_info and not mfr:
                        try:
                            mfr, model = chip_info.split(maxsplit=1)
                        except ValueError:
                            mfr, model = '', chip_info
                
                        
                if badblock_map:
                    badblock_map.parse_line(line)
            
                                          
            elif '%' in output_line:
                match = re.search(r'(Erase|Written|Read|Verify|Verifying)\s+(\d+)%', output_line, re.IGNORECASE)
                if match:
                    pct = int(match.group(2))
                    action = match.group(1).lower()
                    if 'verify' in action:
                        current_phase = 'verify'
                    if pct != last_progress:
                        last_progress = pct
                        window.write_event_value('-PROGRESS_EVENT-', pct)
        
                
        if output_line.strip():
            window.write_event_value('-OUTPUT-', output_line.strip())
        
                                                           
        if operation == '读取芯片ID':
            window.write_event_value('-THREAD-', (
                not failed, '\n'.join(captured_lines), device_id, chip_info, chip_size, oob_size, 
                ecc_status, mfr, model
            ))
        
                        
        if operation == '读取':
            file_path = values.get('-READ_FILENAME-', '')
            if file_path and os.path.exists(file_path):
                try:
                    update_hex_preview(window, file_path)
                except Exception as e:
                    print(f"更新Hex预览失败: {e}")
        
                                         
        if not failed and not user_stop_event.is_set():
            window.write_event_value('-PROGRESS_EVENT-', 100)
        elif failed:
            window.write_event_value('-OUTPUT-', '[失败] 操作未完成，请检查上方输出')
        
    except Exception as e:
        print(f"Run command error: {e}")
        window.write_event_value('-OUTPUT-', f"[错误] {str(e)}")
    finally:
        if process is not None:
            return_code = process.poll()

            if stop_event.is_set():
                print(f"命令已终止: {command}")
                print(f"进程 PID: {process.pid}, 返回码: {return_code}")

            elif return_code == 0:
                print(f"命令执行完成: {command}")

            else:
                print(f"命令执行结束，返回码: {return_code}: {command}")
        current_process = None

                                         
device_status_text = '未检测到设备'
status_override_until = 0.0

def update_status(window, message, transient=True):
    global status_override_until
    try:
        window['-STATUS-'].update(message)
        status_override_until = time.time() + 3 if transient else 0.0
    except Exception:
        pass

def restore_device_status(window):
    global status_override_until
    if status_override_until and time.time() >= status_override_until:
        status_override_until = 0.0
        try:
            window['-STATUS-'].update(device_status_text)
        except Exception:
            pass

def fix_progressbar_length(element, pixels):
    try:
        widget = element.Widget
        ttk_bar = getattr(widget, 'TKProgressBarForReal', getattr(widget, 'TKProgressBar', widget))
        ttk_bar.configure(length=pixels)
    except Exception:
        pass

def fit_hex_preview_font(window):
    try:
        import tkinter.font as tkfont
        element = window['-HEX_PREVIEW_RIGHT-']
        text = element.Widget
        window.TKroot.update_idletasks()
        inner_px = text.winfo_reqwidth() - 4                   
        if inner_px <= 0:
            return
                                                    
        size = HEX_PREVIEW_BASE_SIZE
        chosen = tkfont.Font(family=HEX_PREVIEW_FONT, size=size)
        for s in range(HEX_PREVIEW_BASE_SIZE + 1, HEX_PREVIEW_BASE_SIZE + 8):
            probe = tkfont.Font(family=HEX_PREVIEW_FONT, size=s)
            if HEX_LINE_CHARS * probe.measure('0') <= inner_px:
                size, chosen = s, probe
            else:
                break
        new_font = chosen

        old_h = text.winfo_reqheight()                         
        linespace = new_font.metrics('linespace') or 17
        rows = max(10, int(old_h / linespace))
                                      
        width_chars = max(HEX_LINE_CHARS, int(inner_px / new_font.measure('0')))
        text.configure(font=new_font, width=width_chars, height=rows)
        element.Font = (HEX_PREVIEW_FONT, size)                            
    except Exception:
        pass

def fit_right_column(window):
    try:
        window.TKroot.update_idletasks()
        hex_f = window['-HEX_FRAME_RIGHT-'].Widget
        bb_f = window['-BADBLOCK_FRAME-'].Widget
        target = max(hex_f.winfo_reqwidth(), bb_f.winfo_reqwidth())
        for f in (hex_f, bb_f):
                                                          
                            
            f.configure(width=target, height=f.winfo_reqheight())
            f.pack_propagate(False)
                                                       
                                                          
        canvas_w = target - 14
        g = window['-BADBLOCK_MAP-']
        g.CanvasSize = (canvas_w, 120)
        g.BottomLeft = (0, 0)
        g.TopRight = (canvas_w, 120)
        g.Widget.configure(width=canvas_w, height=120, scrollregion=(0, 0, canvas_w, 120))
                                 
        fit_hex_preview_font(window)
        window.refresh()
    except Exception:
        pass

if __name__ == '__main__':    
    custom_popup_disclaimer()

    def check_required_exes():
        programmers = ['CH341A', 'CH347T/F']
        missing = []
        for prog in programmers:
            exe_path = get_programmer_exe(prog)   
            if not os.path.exists(exe_path):
                missing.append(os.path.basename(exe_path))
        if missing:
            custom_popup_error(
                f"缺少必要的 EXE 文件：{', '.join(missing)}\n请将它们复制到程序所在目录。",
                resource_path('SNANDer_x64.ico')   
)
                                             
                         
    
    check_required_exes()         
    selected_programmer = load_programmer_choice()
    
    window = sg.Window(
        'SNANDer UI 3.2.7 for 1.7.9   2026/10/04    8-Pack Abs', layout, 
        icon=resource_path('SNANDer_x64.ico'), 
                                         
                                                 
                                                             
        resizable=False,
        finalize=True
    )
    update_menu(window, selected_programmer)

                                        
    fix_progressbar_length(window['-REAL_PROGRESS-'], progressbar_px(31))
                                                        
                                         
    fit_right_column(window)
    update_status(window, device_status_text, transient=False)                

    device_monitor = DeviceMonitor(window)
    device_monitor.perform_initial_scan()
    
             
    badblock_map = BadBlockMap(window)

    while True:
        event, values = window.read(timeout=100)

                                            
        restore_device_status(window)
        
        if event in (None, 'Exit', '退出'):
            break
            
        elif event == 'Flash Support List':
            show_flash_support_list()
            
        elif event == '-SHOW_SAVE_FILE_PROMPT-':
            show_save_file_prompt()
            
        elif event == '-DEVICE_CHANGE-':
                                      
            device_status_text = values[event]
            update_status(window, device_status_text, transient=False)

        elif event == '-AUTO_SELECT_PROGRAMMER-':
                                     
            programmer = values[event]
            if programmer and programmer != selected_programmer:
                selected_programmer = programmer
                save_programmer_choice(programmer)
                update_menu(window, selected_programmer)
                                                     
                print(f"[AUTO] 检测到设备，自动选择编程器: {programmer}")
            
        elif event == '-DEVICE_NOT_FOUND-':
            window.bring_to_front()
            custom_popup_error(values[event], resource_path('SNANDer_x64.ico'))

        elif '::select_programmer' in event:
            parts = event.split('::')
            if len(parts) == 2:
                                                       
                                             
                selected_programmer = parts[0].replace('✓', '').strip()
                save_programmer_choice(selected_programmer)
                update_menu(window, selected_programmer)
                print(f"Selected programmer: {selected_programmer}")
                update_status(window, f"已选 {selected_programmer}")
        elif '::select_speed' in event:
            parts = event.split('::')
            if len(parts) == 2:
                selected_spi_speed = parts[0].replace('✓', '').strip()
            update_menu(window, selected_programmer)
            update_status(window, f"{selected_programmer} @ {selected_spi_speed}")

        elif event == '-FILENAME-' and values['-FILENAME-']:
            file_path = values['-FILENAME-']
            print(f"选择了文件: {file_path}")
            if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                update_hex_preview(window, file_path)
            else:
                print(f"文件不可访问或不存在: {file_path}")
                custom_popup_error(f"文件不可访问或不存在: {file_path}", resource_path('SNANDer_x64.ico'))
                
        elif event in ['-ADDRESS-', '-LENGTH-'] and values['-FILENAME-']:
            try:
                offset = int(values['-ADDRESS-'], 16)
                length = int(values['-LENGTH-'])
                file_path = values['-FILENAME-']
                update_hex_preview(window, file_path, offset, length)
            except ValueError:
                window['-HEX_PREVIEW_RIGHT-'].update("请输入有效的地址和长度")

        elif event == '提交':
            pass

        if event in ['-READ_CHIP_ID-', '-READ-', '-WRITE-', '-ERASE-']:
            if badblock_map:
                badblock_map.clear()
            thread_function(event, values, window)

        elif event == '-PROGRESS_EVENT-':
            progress_value = values[event]
            
                           
            color_map = {
                '读取芯片ID': ("#BCD9F1", 'light gray'),       
                '读取': ('#2196F3', 'light gray'),             
                '写入': ('#24f901', 'light gray'),             
                '擦除': ("#FF1E00", 'light gray'),             
            }
            
                            
            if current_operation == '写入' and current_phase == 'verify':
                bar_color = ('#9C27B0', 'light gray')          
            else:
                bar_color = color_map.get(current_operation, ('#9C27B0', 'light gray'))
            
            window['-REAL_PROGRESS-'].update(current_count=progress_value, bar_color=bar_color)
            window['-PROGRESS_PCT-'].update(f"{progress_value}%")  


        elif event == '-OUTPUT-':
            line = values['-OUTPUT-']
            if not line or not line.strip():
                continue
            
            if 'SNANDer - Serial' in line and 'McMCC' in line:
                continue
            
            if "Status:" in line:
                formatted = f"★ {line.strip()}\n"
            elif any(x in line for x in ["Erase", "Write", "Read", "Verify", "Written"]):
                formatted = f"▶ {line.strip()}\n"
            else:
                formatted = f"  {line.strip()}\n"
            
            window['-HEX_PREVIEW-'].print(formatted, end='')

        elif event == '停止':

            user_stop_event.set()
            stop_event.set()

            if current_process:
                pid = current_process.pid

                print(f"[STOP] 正在终止进程 PID={pid}")

                try:
                    current_process.terminate()
                    print(f"[STOP] SNANDer 已终止 PID={pid}")
                except Exception as e:
                    print(f"[STOP] 终止失败: {e}")

            window['-HEX_PREVIEW-'].print(
                "\n操作已终止。\n",
                end=''
            )

            window['-REAL_PROGRESS-'].update(
                current_count=0
    )
                
        elif event == 'Firmware Compare':
            show_firmware_compare(window)

        elif event == '-THREAD-':
            success, output, device_id, chip_info, chip_size, oob_size, ecc_status, mfr, model = values[event]
            if success:
                window['-DEVICE_ID-'].update(device_id or '')
                window['-MFR-'].update(mfr)
                window['-MODEL-'].update(model)
                window['-CHIP_SIZE-'].update(chip_size or '')
                window['-OOB_SIZE_DISPLAY-'].update(oob_size or '')
                window['-ECC_STATUS-'].update(ecc_status or '')
                                                   
                                         
                window['-REAL_PROGRESS-'].update(current_count=0)
                window['-PROGRESS_PCT-'].update("0%")
                
                                                                           
            if chip_size and ('nand' in (model or '').lower() or 
                             'oob' in str(oob_size).lower() or
                             str(oob_size).strip()):
                
                                           
                block_size_kb = None
                if output:                 
                    match = re.search(r'block[:\s]+(\d+)\s*KB', output, re.I)
                    if match:
                        block_size_kb = int(match.group(1))
                
                badblock_map.init_chip(chip_size, block_size_kb)
            else:
                                                             
                badblock_map.show_no_chip()

        elif event == 'About':
            about_layout = [
                [sg.Image(filename=background_image_path, key='-BACKGROUND-')],
                [sg.Text('')],
                [sg.Text('Copyright 2025-2026 8-Pack Abs. All rights reserved.')],
                [sg.Button('确定')]
            ]
            about_window = sg.Window('About SNANDer UI', about_layout, 
                                   icon=resource_path('SNANDer_x64.ico'), 
                                   element_justification='center')
            while True:
                event, values = about_window.read()
                if event in (sg.WIN_CLOSED, '确定'):
                    about_window.close()
                    break

    window.close()