import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk


# class Handler:
#     def onDestroy(self, *args):
#         Gtk.main_quit()

#     def onButtonPressed(self, button):
#         print("Hello World!")

# def on_btn1_clicked(self,widget):
#     print("deniyoruz aga")

# builder = Gtk.Builder()
# builder.add_from_file("deneme2.glade")
# #builder.connect_signals(Handler())

# window = builder.get_object("window1")

# window.show_all()

# Gtk.main()

class Main:
    def __init__(self):
        gladeFile = "deneme2.glade"
        self.builder = Gtk.Builder()
        self.builder.add_from_file(gladeFile)
        self.builder.connect_signals(self)

        self.treeview = self.builder.get_object("treeView")
        self.pathListStore = Gtk.ListStore(str)
        window = self.builder.get_object("window1")
        
        self.populateTreeView()

        window.connect("delete-event", Gtk.main_quit)
        window.show()

    def populateTreeView(self):
        pass1 = ["abc","klm","hello"]
        for elem in pass1:
            self.pathListStore.append([elem])

        renderer = Gtk.CellRendererText()
        pathColumn = Gtk.TreeViewColumn(title="deneme",cell_renderer=renderer,text=0)
        self.treeview.append_column(pathColumn)
        self.treeview.set_model(self.pathListStore)


if __name__ == '__main__':
    main = Main()
    Gtk.main()