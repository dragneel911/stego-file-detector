(function () {
    const dropzone = document.getElementById("dropzone");
    const input = document.getElementById("file-input");
    const text = document.getElementById("dropzone-text");
    const form = document.getElementById("scan-form");
    const button = document.getElementById("scan-button");

    if (!dropzone || !input || !text || !form || !button) return;

    const defaultText = text.textContent;

    function showFilename() {
        if (input.files && input.files.length > 0) {
            text.textContent = input.files[0].name;
        } else {
            text.textContent = defaultText;
        }
    }

    input.addEventListener("change", showFilename);

    ["dragenter", "dragover"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropzone.classList.add("is-dragover");
        });
    });

    ["dragleave", "drop"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropzone.classList.remove("is-dragover");
        });
    });

    dropzone.addEventListener("drop", (e) => {
        const files = e.dataTransfer && e.dataTransfer.files;
        if (files && files.length > 0) {
            input.files = files;
            showFilename();
        }
    });

    form.addEventListener("submit", () => {
        button.disabled = true;
        button.textContent = "Scanning...";
    });
})();
