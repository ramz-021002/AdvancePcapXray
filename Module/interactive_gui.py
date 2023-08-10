import sys
if sys.platform == 'darwin':
    import matplotlib
    matplotlib.use('TkAgg')

interactive_graph_support = False
try:
    from cefpython3 import cefpython as cef
    interactive_graph_support = True
except:
    print("Interactive graph in app wont work as python version/platform is not supported (will launch in default browser)")
    pass

import memory
import ctypes
import sys
import os
import platform
import logging as _logging

# Platforms
WINDOWS = (platform.system() == "Windows")
LINUX = (platform.system() == "Linux")
MAC = (platform.system() == "Darwin")
logger = _logging.getLogger("tkinter_.py")

interactive_map = ""
def gimmick_initialize(window, map):
        import webbrowser
        webbrowser.open(interactive_map)

def show_frame(self, cont):
    frame = self.frames[cont]
    frame.tkraise()

class BrowserFrame():

    def __init__(self, master):
        self.closing = False
        self.browser = None
        self.bind("<Configure>", self.on_configure)
        self.focus_set()

    def embed_browser(self):
        assert self.browser
        self.browser.SetClientHandler(LoadHandler(self))
        self.browser.SetClientHandler(FocusHandler(self))
        self.message_loop_work()

    def get_window_handle(self):
        import webbrowser
        webbrowser.open(interactive_map)

    def message_loop_work(self):
        cef.MessageLoopWork()
        self.after(10, self.message_loop_work)

    def on_configure(self, _):
        if not self.browser:
            self.embed_browser()

class LoadHandler(object):

    def __init__(self, browser_frame):
        self.browser_frame = browser_frame

class FocusHandler(object):

    def __init__(self, browser_frame):
        self.browser_frame = browser_frame

    def OnTakeFocus(self, next_component, **_):
        logger.debug("FocusHandler.OnTakeFocus, next={next}"
                     .format(next=next_component))

    def OnSetFocus(self, source, **_):
        logger.debug("FocusHandler.OnSetFocus, source={source}"
                     .format(source=source))
        return False

    def OnGotFocus(self, **_):
        logger.debug("FocusHandler.OnGotFocus")
        self.browser_frame.focus_set()



