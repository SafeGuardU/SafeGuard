import random
import string
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
        my_label = qtw.QLabel("Number of Characters")
        # change font size of label
        my_label.setFont(qtg.QFont('Helvetica', 20))
        self.layout().addWidget(my_label) 

        # create a spin box
        self.my_spin = qtw.QSpinBox(self, value=12, maximum=100, minimum=8, singleStep=1)
        self.my_spin.setFont(qtg.QFont('Helvetica', 18))

        # put spin box on screen
        self.layout().addWidget(self.my_spin) 
        
        # create a button
        my_button = qtw.QPushButton("Generate", clicked=self.press_it) 
        self.layout().addWidget(my_button) 

        # create a label
        self.my_label2 = qtw.QLabel("")
        # change font size of label
        self.my_label2.setFont(qtg.QFont('Helvetica', 20))
        self.layout().addWidget(self.my_label2) 
        
        # show the app
        self.show()

    def generate_password(self, length):
        if length < 4:
            raise ValueError("Password length should be at least 4 characters.")

        # Define character sets for password generation
        lowercase_letters = string.ascii_lowercase
        uppercase_letters = string.ascii_uppercase
        digits = string.digits
        symbols = string.punctuation
        
        # Combine all character sets
        all_characters = lowercase_letters + uppercase_letters + digits + symbols
        
        # Generate a password with at least one character from each character set
        password = (
            random.choice(lowercase_letters) +
            random.choice(uppercase_letters) +
            random.choice(digits) +
            random.choice(symbols)
        )
        
        # Fill the rest of the password with random characters from all_characters
        password += ''.join(random.choice(all_characters) for _ in range(length - 4))
        
        # Shuffle the password to make it more random
        password_list = list(password)
        random.shuffle(password_list)
        password = ''.join(password_list)
        
        return password

    def press_it(self):
        length = self.my_spin.value()
        password = self.generate_password(length)
        self.my_label2.setText(f'{password}')

app = qtw.QApplication([])
mw = MainWindow()
app.exec()
