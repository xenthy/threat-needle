import threading


class Thread:
    @staticmethod
    def set_name(name):
        threading.current_thread().setName(name)

    @staticmethod
    def name():
        return threading.current_thread().getName()
