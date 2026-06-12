// static/js/script.js

document.addEventListener('DOMContentLoaded', () => {
    const startButton = document.getElementById('startButton');
    const stopButton = document.getElementById('stopButton');
    const clearButton = document.getElementById('clearButton');
    const uploadPcapButton = document.getElementById('uploadPcapButton');
    const applyBlocksButton = document.getElementById('applyBlocksButton');
    const refreshBlocksButton = document.getElementById('refreshBlocksButton');

    const interfaceSelect = document.getElementById('interfaceSelect');
    const refreshInterfacesButton = document.getElementById('refreshInterfacesButton');
    const filterInput = document.getElementById('filter');
    const domainFilterInput = document.getElementById('domainFilter');
    const pcapFileInput = document.getElementById('pcapFile');

    const sourceIpsBlockTextarea = document.getElementById('sourceIpsBlock');
    const destIpsBlockTextarea = document.getElementById('destIpsBlock');
    const domainsBlockTextarea = document.getElementById('domainsBlock');
    const blockStatusList = document.getElementById('blockStatusList');

    const statusMessageDiv = document.getElementById('statusMessage');
    const pcapStatusMessageDiv = document.getElementById('pcapStatusMessage');
    const packetTableBody = document.querySelector('#packetTable tbody');
    const flaggedPacketTableBody = document.querySelector('#flaggedPacketTable tbody');
    const totalPacketCountSpan = document.getElementById('totalPacketCount');
    const flaggedPacketCountSpan = document.getElementById('flaggedPacketCount');

    // Search elements
    const flaggedSearchInput = document.getElementById('flaggedSearchInput');
    const flaggedSearchButton = document.getElementById('flaggedSearchButton');
    const flaggedClearSearchButton = document.getElementById('flaggedClearSearchButton');
    const allPacketsSearchInput = document.getElementById('allPacketsSearchInput');
    const allPacketsSearchButton = document.getElementById('allPacketsSearchButton');
    const allPacketsClearSearchButton = document = document.getElementById('allPacketsClearSearchButton');

    let fetchPacketsIntervalId = null;
    let fetchFlaggedPacketsIntervalId = null;
    let fetchStatusIntervalId = null; // Interval for status updates
    let fetchBlockStatusIntervalId = null;

    let allPacketsData = []; // Stores all fetched packets
    let flaggedPacketsData = []; // Stores all fetched flagged packets

    const MAX_DISPLAY_ROWS = 500; // Limit rows for performance

    // --- Utility Functions ---

    /**
     * Displays a status message in the UI.
     * @param {string} message The message to display.
     * @param {'success'|'error'|'info'} type The type of message for styling.
     * @param {HTMLElement} targetDiv The div element to display the message in.
     */
    function showStatusMessage(message, type, targetDiv = statusMessageDiv) {
        targetDiv.textContent = message;
        targetDiv.className = `status-message status-${type}`;
        setTimeout(() => {
            targetDiv.textContent = '';
            targetDiv.className = 'status-message';
        }, 5000); // Clear message after 5 seconds
    }

    /**
     * Fetches the current capture/analysis status from the backend.
     * @returns {Promise<{is_capturing: boolean, is_analyzing_pcap: boolean}>}
     */
    async function getStatus() {
        try {
            const response = await fetch('/get_status');
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error fetching status:', error);
            showStatusMessage('Failed to connect to backend. Is the server running?', 'error');
            return { is_capturing: false, is_analyzing_pcap: false };
        }
    }

    /**
     * Updates the state of UI buttons based on the current capture/analysis status.
     */
    async function updateButtons() {
        const status = await getStatus();

        // Enable/disable main action buttons
        startButton.disabled = status.is_capturing || status.is_analyzing_pcap;
        stopButton.disabled = !(status.is_capturing || status.is_analyzing_pcap);
        uploadPcapButton.disabled = status.is_capturing || status.is_analyzing_pcap;
        pcapFileInput.disabled = status.is_capturing || status.is_analyzing_pcap;

        // Interface controls
        interfaceSelect.disabled = status.is_capturing || status.is_analyzing_pcap;
        refreshInterfacesButton.disabled = status.is_capturing || status.is_analyzing_pcap;

        // Blocking controls
        applyBlocksButton.disabled = status.is_analyzing_pcap; // Can apply blocks only during live capture or when idle

        // Manage intervals and status messages
        if (status.is_capturing) {
            showStatusMessage('Live capture running...', 'info', statusMessageDiv);
            showStatusMessage('', 'info', pcapStatusMessageDiv); // Clear PCAP message
            startFetchingPackets();
            startFetchingFlaggedPackets();
            startFetchingBlockStatus(); // Start fetching active blocks
        } else if (status.is_analyzing_pcap) {
            showStatusMessage('PCAP analysis in progress...', 'info', statusMessageDiv);
            showStatusMessage('Analysis running...', 'info', pcapStatusMessageDiv);
            startFetchingPackets();
            startFetchingFlaggedPackets();
            stopFetchingBlockStatus(); // No active blocks during passive analysis
        } else {
            showStatusMessage('Ready.', 'info', statusMessageDiv);
            showStatusMessage('', 'info', pcapStatusMessageDiv); // Clear PCAP message
            stopFetchingPackets();
            stopFetchingFlaggedPackets();
            startFetchingBlockStatus(); // Always fetch block status when idle
        }
    }

    /**
     * Starts the interval for fetching all packets.
     */
    function startFetchingPackets() {
        if (!fetchPacketsIntervalId) {
            fetchPacketsIntervalId = setInterval(fetchPackets, 1000); // Fetch every 1 second
        }
    }

    /**
     * Stops the interval for fetching all packets.
     */
    function stopFetchingPackets() {
        if (fetchPacketsIntervalId) {
            clearInterval(fetchPacketsIntervalId);
            fetchPacketsIntervalId = null;
        }
    }

    /**
     * Starts the interval for fetching flagged packets.
     */
    function startFetchingFlaggedPackets() {
        if (!fetchFlaggedPacketsIntervalId) {
            fetchFlaggedPacketsIntervalId = setInterval(fetchFlaggedPackets, 1500); // Fetch every 1.5 seconds
        }
    }

    /**
     * Stops the interval for fetching flagged packets.
     */
    function stopFetchingFlaggedPackets() {
        if (fetchFlaggedPacketsIntervalId) {
            clearInterval(fetchFlaggedPacketsIntervalId);
            fetchFlaggedPacketsIntervalId = null;
        }
    }

    /**
     * Starts the interval for fetching block status.
     */
    function startFetchingBlockStatus() {
        if (!fetchBlockStatusIntervalId) {
            fetchBlockStatusIntervalId = setInterval(fetchBlockStatus, 3000); // Fetch every 3 seconds
        }
    }

    /**
     * Stops the interval for fetching block status.
     */
    function stopFetchingBlockStatus() {
        if (fetchBlockStatusIntervalId) {
            clearInterval(fetchBlockStatusIntervalId);
            fetchBlockStatusIntervalId = null;
        }
    }

    /**
     * Fetches all packets from the backend and updates the 'All Packets' table.
     */
    async function fetchPackets() {
        try {
            const response = await fetch('/get_packets');
            allPacketsData = await response.json(); // Store full data
            renderTable('packetTable', allPacketsSearchInput.value, allPacketsData);
            totalPacketCountSpan.textContent = allPacketsData.length;
        } catch (error) {
            console.error('Error fetching all packets:', error);
            // Don't stop interval here, let updateButtons handle it if backend is truly down
        }
    }

    /**
     * Fetches flagged packets from the backend and updates the 'Flagged Packets' table.
     */
    async function fetchFlaggedPackets() {
        try {
            const response = await fetch('/get_flagged_packets');
            flaggedPacketsData = await response.json(); // Store full data
            renderTable('flaggedPacketTable', flaggedSearchInput.value, flaggedPacketsData);
            flaggedPacketCountSpan.textContent = flaggedPacketsData.length;
        } catch (error) {
            console.error('Error fetching flagged packets:', error);
            // Don't stop interval here
        }
    }

    /**
     * Fetches and displays the current block configuration and active firewall rules.
     */
    async function fetchBlockStatus() {
        try {
            const response = await fetch('/get_blocks_status');
            const status = await response.json();
            blockStatusList.innerHTML = '';

            // Configured Blocks
            blockStatusList.innerHTML += '<li><strong>Configured Source IPs:</strong></li>';
            if (status.source_ips_configured.length > 0) {
                status.source_ips_configured.forEach(ip => blockStatusList.innerHTML += `<li>» ${ip}</li>`);
            } else {
                blockStatusList.innerHTML += '<li>» None</li>';
            }

            blockStatusList.innerHTML += '<li><strong>Configured Destination IPs:</strong></li>';
            if (status.dest_ips_configured.length > 0) {
                status.dest_ips_configured.forEach(ip => blockStatusList.innerHTML += `<li>» ${ip}</li>`);
            } else {
                blockStatusList.innerHTML += '<li>» None</li>';
            }

            blockStatusList.innerHTML += '<li><strong>Configured Domains:</strong></li>';
            if (status.domains_configured.length > 0) {
                status.domains_configured.forEach(domain => blockStatusList.innerHTML += `<li>» ${domain}</li>`);
            } else {
                blockStatusList.innerHTML += '<li>» None</li>';
            }

            // Active IPTables Blocks (only if capturing)
            blockStatusList.innerHTML += '<li><strong>Active Firewall Blocks (if capture running):</strong></li>';
            if (status.active_iptables_blocks.length > 0) {
                status.active_iptables_blocks.forEach(ip => blockStatusList.innerHTML += `<li>» ${ip}</li>`);
            } else {
                blockStatusList.innerHTML += '<li>» None currently active (or no capture running).</li>';
            }

            blockStatusList.scrollTop = blockStatusList.scrollHeight; // Scroll to bottom
        } catch (error) {
            console.error('Error fetching block status:', error);
            blockStatusList.innerHTML = '<li>Error loading block status. Check server logs.</li>';
        }
    }

    /**
     * Renders packets into a specific table, applying search filters.
     * @param {string} tableId The ID of the table to render into ('packetTable' or 'flaggedPacketTable').
     * @param {string} query The search query string.
     * @param {Array<Object>} data The full array of packet data to filter and render.
     */
    function renderTable(tableId, query, data) {
        const tableBody = document.querySelector(`#${tableId} tbody`);
        tableBody.innerHTML = ''; // Clear current display

        const lowerCaseQuery = query.toLowerCase();
        const filteredPackets = data.filter(packet => {
            // Combine relevant fields for searching based on table type
            let searchableText = `${packet.timestamp} ${packet.src_ip} ${packet.dst_ip} ${packet.protocol} ${packet.length} ${packet.summary} ${packet.raw_payload}`.toLowerCase();
            if (tableId === 'flaggedPacketTable') {
                searchableText += ` ${packet.targeted_reasons.join(' ')} ${packet.intrusion_reasons.join(' ')}`.toLowerCase();
            } else { // 'packetTable'
                const flags = [];
                if (packet.is_targeted_flagged) flags.push('targeted');
                if (packet.is_intrusion_flagged) flags.push('intrusion');
                searchableText += ` ${flags.join(' ')}`.toLowerCase();
            }
            return searchableText.includes(lowerCaseQuery);
        });

        // Display only the latest MAX_DISPLAY_ROWS
        const packetsToDisplay = filteredPackets.slice(-MAX_DISPLAY_ROWS);

        packetsToDisplay.forEach(packet => {
            const row = tableBody.insertRow(0); // Insert at the top for newest packets

            // Apply row highlighting based on flags
            if (packet.is_targeted_flagged && packet.is_intrusion_flagged) {
                row.classList.add('flagged-both');
            } else if (packet.is_targeted_flagged) {
                row.classList.add('flagged-targeted');
            } else if (packet.is_intrusion_flagged) {
                row.classList.add('flagged-intrusion');
            }

            row.insertCell(0).textContent = packet.timestamp;
            row.insertCell(1).textContent = packet.src_ip;
            row.insertCell(2).textContent = packet.dst_ip;
            row.insertCell(3).textContent = packet.protocol;
            row.insertCell(4).textContent = packet.length;
            row.insertCell(5).textContent = packet.summary;

            if (tableId === 'flaggedPacketTable') {
                // For flagged table, combine reasons and show payload
                const reasons = [...packet.intrusion_reasons, ...packet.targeted_reasons].filter(Boolean); // Filter out empty strings
                row.insertCell(6).textContent = reasons.join('; ');
                row.insertCell(7).textContent = packet.raw_payload;
            } else { // 'packetTable'
                // For all packets table, show raw payload and flag indicators
                row.insertCell(6).textContent = packet.raw_payload;
                const flagsCell = row.insertCell(7);
                let flagsHtml = [];
                if (packet.is_targeted_flagged) {
                    flagsHtml.push('<span class="flag-indicator" title="Targeted Monitoring">T</span>');
                }
                if (packet.is_intrusion_flagged) {
                    flagsHtml.push('<span class="flag-indicator" title="Intrusion Detected">I</span>');
                }
                flagsCell.innerHTML = flagsHtml.join(' ');
            }
        });

        // Auto-scroll to the bottom (only if not currently searching)
        if (!query) {
             tableBody.parentElement.scrollTop = tableBody.parentElement.scrollHeight;
        }
    }


    // --- Interface Dropdown Population ---
    /**
     * Fetches and populates the network interfaces dropdown.
     */
    async function populateInterfacesDropdown() {
        try {
            const response = await fetch('/get_interfaces');
            const interfaces = await response.json();

            interfaceSelect.innerHTML = ''; // Clear existing options

            // Add default "Any" option
            const anyOption = document.createElement('option');
            anyOption.value = 'any';
            anyOption.textContent = 'Any (Auto-detect)';
            interfaceSelect.appendChild(anyOption);

            // Add detected interfaces
            // The app.py now returns {name, display_name} objects for Windows, or strings for Linux/macOS
            // The JSON response from app.py will be an array.
            // If there's an 'error' key, it means the backend returned an error object.
            if (interfaces && interfaces.error) {
                console.error("Error fetching interfaces:", interfaces.message);
                showStatusMessage(`Error loading interfaces: ${interfaces.message}`, 'error', statusMessageDiv);
                const errorOption = document.createElement('option');
                errorOption.value = '';
                errorOption.textContent = `Error: ${interfaces.message.substring(0, 50)}...`;
                errorOption.disabled = true;
                interfaceSelect.appendChild(errorOption);
            } else if (Array.isArray(interfaces)) {
                interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    if (typeof iface === 'object' && iface !== null && 'name' in iface && 'display_name' in iface) {
                        // This is the Windows case (object with name and display_name)
                        option.value = iface.name;
                        option.textContent = iface.display_name;
                    } else {
                        // This is the Linux/macOS case (string name)
                        option.value = iface;
                        option.textContent = iface;
                    }
                    interfaceSelect.appendChild(option);
                });
            } else {
                 console.error("Unexpected interface response format:", interfaces);
                 showStatusMessage('Unexpected interface data format from backend.', 'error', statusMessageDiv);
            }

        } catch (error) {
            console.error('Failed to fetch interfaces:', error);
            interfaceSelect.innerHTML = '<option value="any">Any (Error loading interfaces)</option>';
            showStatusMessage('Failed to load network interfaces. Ensure the Flask app is running and accessible.', 'error', statusMessageDiv);
        }
    }


    // --- Event Listeners ---
    startButton.addEventListener('click', async () => {
        const interfaceVal = interfaceSelect.value;
        const filterVal = filterInput.value;
        const domainFilterVal = domainFilterInput.value;

        const formData = new FormData();
        formData.append('interface', interfaceVal);
        formData.append('filter', filterVal);
        formData.append('domain_filter', domainFilterVal);

        try {
            const response = await fetch('/start_capture', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            showStatusMessage(data.message, data.status === 'success' ? 'success' : 'error');
            updateButtons(); // Update button states based on new status
        } catch (error) {
            console.error('Error starting capture:', error);
            showStatusMessage('Failed to start capture. Check console for details.', 'error');
            updateButtons(); // Try to update in case of error
        }
    });

    stopButton.addEventListener('click', async () => {
        try {
            const response = await fetch('/stop_capture', {
                method: 'POST'
            });
            const data = await response.json();
            showStatusMessage(data.message, data.status === 'success' ? 'success' : 'error');
            updateButtons(); // Update button states after stopping
        } catch (error) {
            console.error('Error stopping capture:', error);
            showStatusMessage('Failed to stop capture. Check console for details.', 'error');
            updateButtons(); // Try to update in case of error
        }
    });

    clearButton.addEventListener('click', async () => {
        try {
            const response = await fetch('/clear_packets', {
                method: 'POST'
            });
            const data = await response.json();
            showStatusMessage(data.message, data.status);
            if (data.status === 'success') {
                allPacketsData = [];
                flaggedPacketsData = [];
                packetTableBody.innerHTML = '';
                flaggedPacketTableBody.innerHTML = '';
                totalPacketCountSpan.textContent = '0';
                flaggedPacketCountSpan.textContent = '0';
                allPacketsSearchInput.value = ''; // Clear search input
                flaggedSearchInput.value = ''; // Clear search input
            }
        } catch (error) {
            console.error('Error clearing packets:', error);
            showStatusMessage('Failed to clear packets. Check console for details.', 'error');
        }
    });

    uploadPcapButton.addEventListener('click', async () => {
        const file = pcapFileInput.files[0];
        const domainFilterVal = domainFilterInput.value;

        if (!file) {
            showStatusMessage('Please select a PCAP file to upload.', 'error', pcapStatusMessageDiv);
            return;
        }

        const formData = new FormData();
        formData.append('pcap_file', file);
        formData.append('domain_filter', domainFilterVal);

        showStatusMessage('Uploading and analyzing...', 'info', pcapStatusMessageDiv);
        updateButtons(); // Update buttons immediately to show analysis in progress

        try {
            const response = await fetch('/upload_pcap', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            showStatusMessage(data.message, response.ok ? 'success' : 'error', pcapStatusMessageDiv);
            updateButtons();
        } catch (error) {
            console.error('Error uploading PCAP:', error);
            showStatusMessage(`Failed to upload PCAP: ${error.message}`, 'error', pcapStatusMessageDiv);
            updateButtons();
        }
    });

    applyBlocksButton.addEventListener('click', async () => {
        const sourceIps = sourceIpsBlockTextarea.value;
        const destIps = destIpsBlockTextarea.value;
        const domains = domainsBlockTextarea.value;

        const formData = new FormData();
        formData.append('source_ips_block', sourceIps);
        formData.append('dest_ips_block', destIps);
        formData.append('domains_block', domains);

        try {
            const response = await fetch('/manage_blocks', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            showStatusMessage(data.message, data.status === 'success' ? 'success' : 'error');
            fetchBlockStatus(); // Refresh block status display
        } catch (error) {
            console.error('Error applying blocks:', error);
            showStatusMessage('Failed to apply blocks. Check console for details.', 'error');
        }
    });

    refreshBlocksButton.addEventListener('click', fetchBlockStatus);
    refreshInterfacesButton.addEventListener('click', populateInterfacesDropdown);

    // --- Search Event Listeners ---
    flaggedSearchButton.addEventListener('click', () => {
        renderTable('flaggedPacketTable', flaggedSearchInput.value, flaggedPacketsData);
    });
    flaggedSearchInput.addEventListener('keyup', () => { // Live search as user types
        renderTable('flaggedPacketTable', flaggedSearchInput.value, flaggedPacketsData);
    });
    flaggedClearSearchButton.addEventListener('click', () => {
        flaggedSearchInput.value = '';
        renderTable('flaggedPacketTable', '', flaggedPacketsData); // Show all
    });

    allPacketsSearchButton.addEventListener('click', () => {
        renderTable('packetTable', allPacketsSearchInput.value, allPacketsData);
    });
    allPacketsSearchInput.addEventListener('keyup', () => { // Live search as user types
        renderTable('packetTable', allPacketsSearchInput.value, allPacketsData);
    });
    allPacketsClearSearchButton.addEventListener('click', () => {
        allPacketsSearchInput.value = '';
        renderTable('packetTable', '', allPacketsData); // Show all
    });

    // Initial setup when the page loads
    populateInterfacesDropdown(); // Populate dropdown on load
    updateButtons(); // Set initial button states and start/stop intervals
    fetchBlockStatus(); // Also fetch initial block status on load
});
