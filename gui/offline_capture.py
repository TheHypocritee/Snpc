import PySimpleGUI as sg
import threading

from scapy.layers.dns import DNS, DNSQR
from scapy.utils import rdpcap

def pcap_to_list(file_path):
    global packets
    packets = rdpcap(file_path)
    packet_summaries = [str(packet.summary()) for packet in packets]
    return packet_summaries
def packet_callback(packet):
    if DNS in packet and DNSQR in packet:
        dns_layer = packet[DNS]
        query = packet[DNSQR].qname.decode('utf-8')
        print(f'Domain: {query}')
    print(packet.show())

def offline_layout():
    layout = [
        [sg.LB([],key='-offline-',size=(80,28),enable_events=True),sg.ML(key='-analyze_o-',size=(30,28),reroute_stdout=True)],
        [sg.In(key='-open_file-', size=(40,1)),sg.FileBrowse('打开文件', target='-open_file-',file_types=(('ALL FILE','.pcap'),))],
        [sg.Col([[sg.B('开始解析', key='-START_ANALYZE-'),
         sg.B('清除',key='-clear2-')]],justification='center')],
    ]
    return layout

def handle_analyze_window_events(event, values, window):
    global packet_list
    global selected_item
    if event == '-START_ANALYZE-':
        file_path = values['-open_file-']
        selected_item = values['-offline-']  # 获取用户在列表框中选择的项
        if values['-open_file-'] != '':
            packet_list = pcap_to_list(file_path)
            window['-offline-'].update(values=packet_list)
        else:sg.popup('请选择文件!')
    if event == '-clear2-':
        window['-offline-'].update('')
    if event == '-offline-':
        window['-analyze_o-'].update('')
        selected_item = values['-offline-']  # 获取用户在列表框中选择的项
        selected_item=''.join(selected_item)
        if selected_item in packet_list:
            index = packet_list.index(selected_item)
            packet_analyze = packet_callback(packets[index])
            window['-analyze_o-'].print(packet_analyze)  # 使用 print 输出到 Multiline 元素
        else:
            print('无信息')





