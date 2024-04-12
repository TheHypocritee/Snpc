
import PySimpleGUI as sg
from gui import filter_capture, census_capture,offline_capture,real_time_capture_window


def main_window():
    menu_def = [['文件(&F)', ['新建文件(&N)', '打开文件(&O)', '保存(&A)', ]],
                    ['设置(&S)'],
                    ['&帮助', '关于'], ]
    capture_layout=real_time_capture_window.real_time_capture_layout()
    analyze_layout=offline_capture.offline_layout()
    filter_layout=filter_capture.filter_layout()
    census_layout=census_capture.census_layout()
    layout = [[sg.Menu(menu_def)],
        [sg.TabGroup([[sg.Tab('实时捕获', capture_layout,key='-capture_layout-', title_color='red'),
                       sg.Tab('离线捕获', analyze_layout,key='-offline_layout-'),
                       sg.Tab('过滤捕获',filter_layout),
                       sg.Tab('统计捕获',census_layout)

                       ]],
                     tab_location='lefttop',
                     title_color='black',  # 未选中
                     tab_background_color='gray',
                     selected_title_color='blue',  # 选中
                     background_color='gray',  # 标签标题所在空白区域的背景颜色
                     selected_background_color='white',  # 选中
                     font=('楷体', 12),
                     enable_events=True,
                     border_width=None,
                     size=(1000,600)
                     )]

    ]

    window = sg.Window('简易网络数据包捕获器',layout,size=(900,600),background_color='Light blue',finalize=True)

    while True:
        event,values = window.read()

        if event == None:
            break
        offline_capture. handle_analyze_window_events(event, values, window)
        real_time_capture_window.handle_realtime_capture_window_events(event, values, window)
        filter_capture.handle_filter_capture_window_events(event, values,window)

    window.close()
