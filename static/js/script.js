document.addEventListener('DOMContentLoaded', () => {
    // Fetch files on page load
    fetchFiles();

    // Add event listener to the upload button
    document.getElementById('uploadBtn').addEventListener('click', uploadFiles);

    // Add event listener to the file input
    document.getElementById('fileInput').addEventListener('change', handleFileSelection);
});

function getCSRFToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

let filesToUpload = [];

function handleFileSelection(event) {
    const files = event.target.files;
    filesToUpload = Array.from(files);
    displaySelectedFiles();
}

function displaySelectedFiles() {
    const selectedFilesDiv = document.getElementById('selectedFiles');
    selectedFilesDiv.innerHTML = '';

    if (filesToUpload.length === 0) {
        selectedFilesDiv.textContent = 'No files selected.';
        return;
    }

    const list = document.createElement('ul');
    filesToUpload.forEach((file, index) => {
        const listItem = document.createElement('li');
        listItem.textContent = `${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
        list.appendChild(listItem);
    });

    selectedFilesDiv.appendChild(list);
}

async function uploadFiles() {
    const statusDiv = document.getElementById('status');
    if (filesToUpload.length === 0) {
        statusDiv.textContent = 'Please select file(s) to upload.';
        statusDiv.style.color = 'red';
        return;
    }

    for (const file of filesToUpload) {
        statusDiv.textContent = `Processing ${file.name}...`;
        statusDiv.style.color = 'black';

        // Compute file hash
        const fileHash = await computeFileHash(file);

        // Check if file exists on server
        const fileExists = await checkFileExists(fileHash, file.name);
        if (fileExists === 'exists' || fileExists === 'associated') {
            statusDiv.textContent = `File "${file.name}" uploaded instantly.`;
            statusDiv.style.color = 'green';
            continue;
        }

        // Perform PoW
        statusDiv.textContent = `Performing Proof of Work for "${file.name}"...`;
        const difficulty = 4; // Adjust as needed
        const challenge = await getChallenge();
        const nonce = await proofOfWork(challenge, difficulty);

        // Upload file
        statusDiv.textContent = `Uploading "${file.name}"...`;

        const formData = new FormData();
        formData.append('file', file);
        formData.append('nonce', nonce);
        formData.append('file_hash', fileHash);

        const csrfToken = getCSRFToken();

        const response = await fetch('/api/upload', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken
            },
            body: formData
        });

        const result = await response.json();
        if (response.ok) {
            statusDiv.textContent = result.message;
            statusDiv.style.color = 'green';
        } else {
            statusDiv.textContent = `Error: ${result.message}`;
            statusDiv.style.color = 'red';
        }
    }

    // Clear selected files and refresh file list
    filesToUpload = [];
    document.getElementById('fileInput').value = '';
    displaySelectedFiles();
    fetchFiles();
}

async function computeFileHash(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = async function (event) {
            const arrayBuffer = event.target.result;
            const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            resolve(hashHex);
        };
        reader.onerror = function (error) {
            reject(error);
        };
        reader.readAsArrayBuffer(file);
    });
}

async function checkFileExists(fileHash, filename) {
    const csrfToken = getCSRFToken();
    const response = await fetch('/api/check_file', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ file_hash: fileHash, filename: filename })
    });
    const result = await response.json();
    return result.status;
}

async function getChallenge() {
    const response = await fetch('/api/get_challenge');
    const data = await response.json();
    return data.challenge;
}

async function proofOfWork(challenge, difficulty) {
    let nonce = 0;
    const maxNonce = Number.MAX_SAFE_INTEGER;
    while (nonce < maxNonce) {
        const hash = await sha256(challenge + nonce);
        if (hash.startsWith('0'.repeat(difficulty))) {
            return nonce.toString();
        }
        nonce++;
    }
    throw new Error('Proof of Work failed');
}

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
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

            const actionsCell = document.createElement('td');

            // Download button
            const downloadBtn = document.createElement('button');
            downloadBtn.textContent = 'Download';
            downloadBtn.className = 'action-btn download-btn';
            downloadBtn.addEventListener('click', () => {
                window.location.href = `/download/${file.id}`;
            });

            // Delete button
            const deleteBtn = document.createElement('button');
            deleteBtn.textContent = 'Delete';
            deleteBtn.className = 'action-btn delete-btn';
            deleteBtn.addEventListener('click', async () => {
                if (confirm('Are you sure you want to delete this file?')) {
                    const csrfToken = getCSRFToken();
                    const response = await fetch(`/delete/${file.id}`, {
                        method: 'POST',
                        headers: {
                            'X-CSRFToken': csrfToken
                        }
                    });
                    const result = await response.json();
                    if (response.ok) {
                        alert(result.message);
                        fetchFiles();  // Refresh the file list
                    } else {
                        alert(`Error: ${result.message}`);
                    }
                }
            });

            actionsCell.appendChild(downloadBtn);
            actionsCell.appendChild(deleteBtn);

            row.appendChild(filenameCell);
            row.appendChild(uploadTimeCell);
            row.appendChild(actionsCell);

            filesTableBody.appendChild(row);
        });
    }
}
