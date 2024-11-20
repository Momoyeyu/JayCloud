async function sha256(message) {
    // Encode as UTF-8
    const msgBuffer = new TextEncoder().encode(message);
    // Hash the message
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    // Convert ArrayBuffer to Array
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    // Convert bytes to hex string
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

async function proofOfWork(challenge, difficulty) {
    let nonce = 0;
    while (true) {
        const hash = await sha256(challenge + nonce);
        if (hash.startsWith('0'.repeat(difficulty))) {
            return nonce.toString();
        }
        nonce++;
    }
}

async function getChallenge() {
    const response = await fetch('/api/get_challenge');
    const data = await response.json();
    return data.challenge;
}

async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const statusDiv = document.getElementById('status');
    if (fileInput.files.length === 0) {
        statusDiv.textContent = 'Please select a file.';
        return;
    }
    statusDiv.textContent = 'Starting Proof of Work...';
    const difficulty = 4; // Adjust difficulty as needed
    const challenge = await getChallenge();
    const nonce = await proofOfWork(challenge, difficulty);
    statusDiv.textContent = 'Proof of Work completed. Uploading file...';

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('nonce', nonce);

    const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
    });

    const result = await response.json();
    if (response.ok) {
        statusDiv.textContent = result.message;
        fetchFiles();  // Refresh the file list
    } else {
        statusDiv.textContent = `Error: ${result.message}`;
    }
}

async function fetchFiles() {
    const response = await fetch('/files');
    const data = await response.json();
    if (data.status === 'success') {
        const filesTableBody = document.querySelector('#filesTable tbody');
        filesTableBody.innerHTML = '';  // Clear existing rows
        data.files.forEach(file => {
            const row = document.createElement('tr');
            const filenameCell = document.createElement('td');
            filenameCell.textContent = file.filename;
            const uploadTimeCell = document.createElement('td');
            uploadTimeCell.textContent = file.upload_time;
            row.appendChild(filenameCell);
            row.appendChild(uploadTimeCell);
            filesTableBody.appendChild(row);
        });
    }
}

document.getElementById('uploadBtn').addEventListener('click', uploadFile);

// Fetch files on page load
window.onload = fetchFiles;
