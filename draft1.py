import PyQt6.QtWidgets as qtw
import PyQt6.QtGui as qtg

class MainWindow(qtw.QWidget):
    def __init__(self):
        super().__init__()
        # set title
        self.setWindowTitle("PASSWORD GENERATOR")
    
        # set vertical layout
        self.setLayout(qtw.QVBoxLayout())

        # create a label
        my_label = qtw.QLabel("Pick how many character you would like your password to be")
        # change font size of label
        my_label.setFont(qtg.QFont('Helvetica', 20))
        self.layout().addWidget(my_label) 
 

        # create a spin box
        my_spin = qtw.QSpinBox(self, value=12, maximum=100, minimum=8, singleStep=1)
        my_spin.setFont(qtg.QFont('Helvetica', 18))

        # put spin box on screen
        self.layout().addWidget(my_spin) 
        
        # create a button
        my_button = qtw.QPushButton("Press Me", clicked=lambda: press_it()) 
        self.layout().addWidget(my_button) 

        # create a label
        my_label2 = qtw.QLabel("")
        # change font size of label
        my_label2.setFont(qtg.QFont('Helvetica', 20))
        self.layout().addWidget(my_label2) 
        
        # show the app
        self.show()

        def press_it():
            my_label2.setText(f'You picked {my_spin.value()}')

app = qtw.QApplication([])
mw = MainWindow()
app.exec()
