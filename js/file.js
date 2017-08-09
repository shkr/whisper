/**
 * Check for the various File API support.
 */
function checkFileAPI() {
    if (window.File && window.FileReader && window.FileList && window.Blob) {
        reader = new FileReader();
        return true; 
    } else {
        alert('The File APIs are not fully supported by your browser. Fallback required.');
        return false;
    }
}

/**
 * read text input
 */
function readText(filePath) {
    var reader = new FileReader()
    if(!checkFileAPI()) {
        alert('file api not available, open app on chrome!')
    } else if(filePath.files && filePath.files[0]) {           
        reader.onload = function (e) {
            output = e.target.result;
            return output;
        };//end onload()
        reader.readAsText(filePath.files[0]);
    }
}