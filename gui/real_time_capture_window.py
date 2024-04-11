import threading
import time

import PySimpleGUI as sg
from scapy.all import sniff, wrpcap

stop_capture_flag = False  # 用于控制捕获停止的全局变量
captured_packets_list = []  # 用于存储捕获的数据包的列表
captured_packets_str  = [] #用于存储捕获的数据包的字符串

def packet_callback(packet):
    # 处理捕获到的数据包，可以在这里输出或存储相关信息
    packet_summary = str(packet.summary())
    captured_packets_list.append(packet)  # 将捕获的数据包存储起来
    captured_packets_str.append([packet_summary])

def real_time_capture_layout():
    layout = [
        [sg.Table(values=[], headings=['数据包'], display_row_numbers=True, auto_size_columns=False,def_col_width=55,
                  justification='left', num_rows=20, key='-real_time_capture_layout-', enable_events=True)],
        [sg.Button('开始捕获', key='-START_CAPTURE-'),
         sg.Button('停止捕获', key='-STOP_CAPTURE-'), sg.Button('清除', key='-clear1-')],
        [sg.In(key='-save_folder-'), sg.FolderBrowse('选择保存文件夹', target='-save_folder-')],
        [sg.Button('保存文件', key='-SAVE_FILE-', disabled=True)]
    ]
    return layout

def handle_realtime_capture_window_events(event, values, window):
    global stop_capture_flag  # 使用全局变量
    if event == '-START_CAPTURE-':
        stop_capture_flag = False  # 重置停止标志
        captured_packets_list.clear()  # 清空之前捕获的数据包
        window['-START_CAPTURE-'].update('重新捕获', disabled=True)
        window['-clear1-'].update(disabled=True)
        window['-real_time_capture_layout-'].update('')
        # 在另一个线程中执行捕获操作
        threading.Thread(target=start_capture, args=(window,), daemon=True).start()
        window['-SAVE_FILE-'].update(disabled=False)  # 启用保存文件按钮
    if event == '-STOP_CAPTURE-':
        stop_capture_flag = True  # 设置停止标志
        window['-SAVE_FILE-'].update(disabled=False)  # 启用保存文件按钮
        window['-START_CAPTURE-'].update(disabled=False)
        window['-clear1-'].update(disabled=False)
    if event == '-SAVE_FILE-':
        save_folder = values['-save_folder-']
        save_captured_packets(captured_packets_list, save_folder)
    if event == '-clear1-':
        window['-real_time_capture_layout-'].update('')

def start_capture(window):
    while not stop_capture_flag:
        time.sleep(0.1)  # Add a small delay to control refresh rate
        sniff(prn=packet_callback, store=0, count=1)
        window['-real_time_capture_layout-'].update(values=captured_packets_str)  # 更新表格的时候提供二维列表

def save_captured_packets(packets, save_folder):
    if not packets:
        sg.popup_error("没有捕获到数据包")
        return

    if not save_folder:
        sg.popup_error("请选择保存文件夹")
        return

    file_path = sg.popup_get_file("保存文件", save_folder, save_as=True, default_extension=".pcap")

    if file_path:
        wrpcap(file_path, packets)
        sg.popup(f"数据包保存成功：{file_path}")
