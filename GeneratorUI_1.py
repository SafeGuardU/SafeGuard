import random
import string
import PyQt6.QtWidgets as qtw
import PyQt6.QtGui as qtg
import PyQt6.QtCore as qtc

class MainWindow(qtw.QWidget):
    def __init__(self):
        super().__init__()
        # set title
        self.setWindowTitle("PASSWORD MANAGER")
        
        # set fixed size
        self.setFixedSize(400, 625)
    
        # set vertical layout
        self.setLayout(qtw.QVBoxLayout())

        # create a slider
        self.my_slider = qtw.QSlider(qtc.Qt.Orientation.Horizontal)
        self.my_slider.setMinimum(8)
        self.my_slider.setMaximum(100)
        self.my_slider.setValue(12)
        self.my_slider.setTickInterval(10)
        self.my_slider.setTickPosition(qtw.QSlider.TickPosition.NoTicks)
        self.my_slider.valueChanged.connect(self.update_slider_label)

        # put slider on screen
        self.layout().addWidget(self.my_slider)

        # create a horizontal layout for the label and input field
        label_input_layout = qtw.QHBoxLayout()

        # create a label
        my_label = qtw.QLabel("Number of Characters:")
        my_label.setFont(qtg.QFont('Helvetica', 13))
        label_input_layout.addWidget(my_label)

        # create an input text field for the slider value
        self.slider_input = qtw.QLineEdit("12")
        self.slider_input.setValidator(qtg.QIntValidator(8, 100))
        self.slider_input.setFixedWidth(50)  # set the fixed width for the input field
        self.slider_input.setFont(qtg.QFont('Helvetica', 18))
        self.slider_input.textChanged.connect(self.update_slider_from_input)
        label_input_layout.addWidget(self.slider_input)

        # add the horizontal layout to the main layout
        self.layout().addLayout(label_input_layout)

        # create checkboxes
        self.include_numbers = qtw.QCheckBox("Include Numbers")
        self.include_numbers.setChecked(True)
        self.layout().addWidget(self.include_numbers)

        self.include_special_chars = qtw.QCheckBox("Include Special Characters")
        self.include_special_chars.setChecked(True)
        self.layout().addWidget(self.include_special_chars)

        # create a button
        my_button = qtw.QPushButton("Generate", clicked=self.press_it)
        self.layout().addWidget(my_button)

        # create a QTextEdit to display the generated password
        self.password_display = qtw.QTextEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setFont(qtg.QFont('Helvetica', 20))
        self.layout().addWidget(self.password_display)

        # create a clipboard icon button
        clipboard_icon = qtg.QIcon.fromTheme("edit-copy")
        self.clipboard_button = qtw.QPushButton("Copy To Clipboard")
        self.clipboard_button.clicked.connect(self.copy_to_clipboard)
        self.layout().addWidget(self.clipboard_button)
        
        # show the app
        self.show()

    def generate_password(self, length, include_special_chars, include_numbers):
        if length < 4:
            raise ValueError("Password length should be at least 4 characters.")

        # Define character sets for password generation
        lowercase_letters = string.ascii_lowercase
        uppercase_letters = string.ascii_uppercase
        digits = string.digits if include_numbers else ''
        symbols = string.punctuation if include_special_chars else ''
        
        # Ensure at least one character set is selected
        if not (lowercase_letters or uppercase_letters or digits or symbols):
            raise ValueError("At least one character set must be enabled.")
        
        # Combine selected character sets
        all_characters = lowercase_letters + uppercase_letters + digits + symbols
        
        # Ensure the password includes at least one character from each enabled set
        password = ''
        if lowercase_letters:
            password += random.choice(lowercase_letters)
        if uppercase_letters:
            password += random.choice(uppercase_letters)
        if digits:
            password += random.choice(digits)
        if symbols:
            password += random.choice(symbols)
        
        # Fill the rest of the password with random characters from all_characters
        password += ''.join(random.choice(all_characters) for _ in range(length - len(password)))
        
        # Shuffle the password to make it more random
        password_list = list(password)
        random.shuffle(password_list)
        password = ''.join(password_list)
        
        return password

    def press_it(self):
        length = self.my_slider.value()
        include_special_chars = self.include_special_chars.isChecked()
        include_numbers = self.include_numbers.isChecked()
        password = self.generate_password(length, include_special_chars, include_numbers)
        self.password_display.setText(password)

    def update_slider_label(self):
        value = self.my_slider.value()
        self.slider_input.setText(str(value))

    def update_slider_from_input(self):
        value = self.slider_input.text()
        if value.isdigit():
            self.my_slider.setValue(int(value))

    def copy_to_clipboard(self):
        clipboard = qtw.QApplication.clipboard()
        clipboard.setText(self.password_display.toPlainText())

app = qtw.QApplication([])
mw = MainWindow()
app.exec()
