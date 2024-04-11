import threading
import time

import PySimpleGUI as sg
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap


stop_capture_flag = False  # 用于控制捕获停止的全局变量
captured_packets_list = []  # 用于存储捕获的数据包的列表
captured_packets_str  = [] #用于存储捕获的数据包的字符串

protocol_list=['ALL','UDP','TCP','ICMP']

def filter_layout():
    layout = [
        [sg.Table(values=[], headings=['数据包'], display_row_numbers=True, auto_size_columns=False,def_col_width=55,
                  justification='left', num_rows=20, key='-filter_layout-', enable_events=True)],
        #协议
        [sg.T('协议 '),sg.Drop(protocol_list,key='-filter_list-',default_value='ALL',size=(10,4))],
        #IP
        [sg.T('IP:',size=(4,1)),sg.T('src_ip>>',size=(8,1)),sg.In('',key='-src_ip-',size=(20,1)),
          sg.T('dst_ip>>',size=(8,1)),sg.In('',key='-dst_ip-',size=(20,1)),
          sg.T('host_ip>>',size=(9,1)),sg.In('',key='-host_ip-',size=(20,1))],
        #端口
        [sg.T('端口:',size=(4,1)), sg.T('src_port>>',size=(8,1)), sg.In('', key='-src_port-', size=(20, 1)),
         sg.T('dst_port>>',size=(8,1)), sg.In('', key='-dst_port-', size=(20, 1)),
         sg.T('host_port>>',size=(9,1)), sg.In('', key='-host_port-', size=(20, 1))],
        [sg.Button('开始捕获', key='-start_filter-'),
         sg.Button('停止捕获', key='-stop_filter-'), sg.Button('清除', key='-clear1-')],
        [sg.In(key='-save_folder-'), sg.FolderBrowse('选择保存文件夹', target='-save_filter_folder-')],
        [sg.Button('保存文件', key='-sava_filter_file-', disabled=True)]
         ]
    return layout



def handle_filter_capture_window_events(event, values, window):
    global stop_capture_flag  # 使用全局变量
    if event == '-start_filter-':
        stop_capture_flag = False  # 重置停止标志
        captured_packets_list.clear()  # 清空之前捕获的数据包
        window['-start_filter-'].update('重新捕获', disabled=True)
        window['-clear1-'].update(disabled=True)
        window['-filter_layout-'].update('')
        # 在另一个线程中执行捕获操作
        threading.Thread(target=start_filter_capture, args=(window,), daemon=True).start()
        window['-sava_filter_file-'].update(disabled=False)  # 启用保存文件按钮
    if event == '-stop_filter-':
        stop_capture_flag = True  # 设置停止标志
        window['-sava_filter_file-'].update(disabled=False)  # 启用保存文件按钮
        window['-start_filter-'].update(disabled=False)
        window['-clear1-'].update(disabled=False)
    if event == '-sava_filter_file-':
        save_folder = values['-save_filter_folder-']
        save_captured_packets(captured_packets_list, save_folder)
    if event == '-clear1-':
        window['-filter_layout-'].update('')

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


def start_filter_capture(window):
    while not stop_capture_flag:
        time.sleep(0.1)  # Add a small delay to control refresh rate
        captured_packets = sniff(prn=lambda pkt: filter_packet(pkt, window), store=0, count=1)
        if captured_packets:
            packet = captured_packets[0]
            # 根据需要处理数据包

            # 判断数据包是否符合过滤条件
            if filter_packet(packet, window):
                captured_packets_str.append([str(packet.summary())])
                window['-filter_layout-'].update(values=captured_packets_str)  # 更新表格的时候提供二维列表
        else:
            # 处理没有捕获到数据包的情况
            print("没有捕获到数据包。")



def filter_packet(packet,window):
    # 根据过滤条件进行判断，返回True表示符合条件，False表示不符合条件
    # 可以根据实际需求修改条件判断
    protocol = window['-filter_list-'].get()
    src_ip = window['-src_ip-'].get()
    dst_ip = window['-dst_ip-'].get()
    src_port = window['-src_port-'].get()
    dst_port = window['-dst_port-'].get()

    # 根据选择的协议进行过滤
    if protocol != 'ALL' and packet.haslayer(protocol.lower()) is False:
        return False

    # 根据IP地址进行过滤
    if src_ip and packet.haslayer('IP') and packet[IP].src != src_ip:
        return False
    if dst_ip and packet.haslayer('IP') and packet[IP].dst != dst_ip:
        return False

    # 根据端口进行过滤
    if src_port and packet.haslayer('TCP') and packet[TCP].sport != int(src_port):
        return False
    if dst_port and packet.haslayer('TCP') and packet[TCP].dport != int(dst_port):
        return False

    return True
