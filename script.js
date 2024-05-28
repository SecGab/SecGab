document.getElementById("addButton").addEventListener("click", function() {
    var textareaContent = document.getElementById("text_ip").value.trim(); // Get textarea content
    if (textareaContent === '') return; // Exit if textarea is empty

    var ipTable = document.getElementById("ip_Table");

    // Clear existing rows from the table
    while (ipTable.rows.length > 1) {
        ipTable.deleteRow(1); // Delete rows starting from index 1 to remove all existing rows except the header row
    }

    var rowCount = 0; // Initialize row count

    // Split the textarea content into individual lines
    var lines = textareaContent.split(/\r?\n/);

    // Loop through each line and add it as a new row to the table
    lines.forEach(function(line) {
        // Validate if the line contains a valid IP address
        if (!isValidIPAddress(line.trim())) {
            alert('Invalid IP address: ' + line.trim());
            return; // Skip processing this line
        }

        var newRow = ipTable.insertRow(); // Create a new row
        rowCount++; // Increment row count

        // Add row count as the first cell in the row
        var countCell = newRow.insertCell(); // Create a new cell for the row count
        countCell.textContent = rowCount; // Set the content of the cell

        // Add the IP address to the second cell in the row
        var ipCell = newRow.insertCell(); // Create a new cell for the IP address
        ipCell.textContent = line.trim(); // Set the content of the cell

        // Determine the IP version (IPv4 or IPv6)
        var ipVersion = getIPVersion(line.trim());

        // Add the IP version to the third cell in the row
        var versionCell = newRow.insertCell(); // Create a new cell for the IP version
        versionCell.textContent = ipVersion; // Set the content of the cell

        // Construct the VirusTotal URL based on the IP address
        var virusTotalURL = 'https://www.virustotal.com/gui/ip-address/' + line.trim() + '/detection';
        var virusTotalLink = document.createElement('a');
        virusTotalLink.href = virusTotalURL;
        virusTotalLink.textContent = virusTotalURL;
        virusTotalLink.target = '_blank';

        // Append the VirusTotal link to the fourth cell in the row
        var virusTotalCell = newRow.insertCell(); // Create a new cell for the Virus Total link
        virusTotalCell.appendChild(virusTotalLink);

        // Construct the IBM X-Force URL based on the IP address
        var xForceURL = 'https://exchange.xforce.ibmcloud.com/ip/' + line.trim();
        var xForceLink = document.createElement('a');
        xForceLink.href = xForceURL;
        xForceLink.textContent = xForceURL;
        xForceLink.target = '_blank';

        // Append the IBM X-Force link to the fifth cell in the row
        var xForceCell = newRow.insertCell(); // Create a new cell for the IBM X-Force link
        xForceCell.appendChild(xForceLink);

        // Add a checkbox as the last cell in the row
        var checkboxCell = newRow.insertCell(); // Create a new cell for the checkbox
        var checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkboxCell.appendChild(checkbox);
    });

    // Clear the textarea after adding its contents to the table
    document.getElementById("text_ip").value = "";

    // Adjust the height of the textarea
    adjustHeight(document.getElementById("text_ip"));
});

document.getElementById("clearButton").addEventListener("click", function() {
    var ipTable = document.getElementById("ip_Table");

    // Clear existing rows from the table
    while (ipTable.rows.length > 1) {
        ipTable.deleteRow(1); // Delete rows starting from index 1 to remove all existing rows except the header row
    }
});

function isValidIPAddress(ip) {
    // Regular expression to match IPv4 address format
    var ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;

    // Regular expression to match IPv6 address format
    var ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

function getIPVersion(ip) {
    // Regular expression to match IPv4 address format
    var ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;

    // Regular expression to match IPv6 address format
    var ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

    if (ipv4Regex.test(ip)) {
        return 'IPv4';
    } else if (ipv6Regex.test(ip)) {
        return 'IPv6';
    } else {
        return 'Unknown';
    }
}
