import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

class Main:
    def __init__(self):
        gladeFile = "deneme2.glade"
        self.builder = Gtk.Builder()
        self.builder.add_from_file(gladeFile)
        self.builder.connect_signals(self)

        self.treeview = self.builder.get_object("treeView")
        self.pathListStore = Gtk.ListStore(str,str)
        window = self.builder.get_object("window1")
        
        self.populateTreeView()

        window.connect("delete-event", Gtk.main_quit)
        window.show()

    def populateTreeView(self):
        pass1 = ["/bin/ls","/bin/cat","/bin/netcat"]
        pass2 = ["User","root","User"]
        for elem in range(0,len(pass1)):
            self.pathListStore.append([pass1[elem],pass2[elem]])

        treeview_columns = ['Binary/Library', 'Privilege']
        for col_num, name in enumerate(treeview_columns):
            # align text in column cells of row (0.0 left, 0.5 center, 1.0 right)
            rendererText = Gtk.CellRendererText(xalign=0.5, editable=False)
            column = Gtk.TreeViewColumn(name ,rendererText, text=col_num)
            self.treeview.set_model(self.pathListStore)
            # center the column titles in first row
            column.set_alignment(0.2)
            # make all the column reorderable, resizable and sortable
            column.set_sort_column_id(col_num)
            column.set_reorderable(True)
            column.set_resizable(True)
            self.treeview.append_column(column)

        # renderer = Gtk.CellRendererText()
        # column = Gtk.TreeViewColumn(title="Binary/Library",cell_renderer=renderer,text=0)
        # self.treeview.append_column(pathColumn)
        #self.treeview.set_model(self.pathListStore)


if __name__ == '__main__':
    main = Main()
    Gtk.main()