import PySimpleGUI as sg

def census_layout():
    layout = [
        [sg.ML( key='-qbq-', size=(100, 27))],
        [sg.In(key='-open_file-', size=(20,1)),sg.FileBrowse('打开文件', file_types=('.pcap'))],
        [sg.B('开始解析', key='-START_ANALYZE-'),
         sg.Button('停止解析', key='-STOP_ANALYZE-'),
         sg.B('清除',key='-clear-')
         ]
    ]
    return layout