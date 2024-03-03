/* if we do end up programming some things in JS it can be convenient to 
use an online complier (https://www.programiz.com/javascript/online-compiler/) instead of mucking around to get it working in 
your own environment every time */ 

function generateRandomPassword(length) {
    var charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    var password = "";
    for (var i = 0; i < length; i++) {
      var randomIndex = Math.floor(Math.random() * charset.length);
      password += charset[randomIndex];
    }
    return password;
  }
  
  // Example usage: generate a random password with length 12
  var newPassword = generateRandomPassword(15);
  console.log(newPassword);
  