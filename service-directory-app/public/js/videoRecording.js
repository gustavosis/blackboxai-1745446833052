'use strict';

const videoPreview = document.getElementById('videoPreview');
const btnRecord = document.getElementById('btnRecord');
const btnPause = document.getElementById('btnPause');
const btnStop = document.getElementById('btnStop');
const btnPlay = document.getElementById('btnPlay');
const btnDownload = document.getElementById('btnDownload');
const recordingHistory = document.getElementById('recordingHistory');

let mediaRecorder;
let recordedChunks = [];
let recordings = [];
let stream;
let isRecording = false;
let isPaused = false;

async function initCamera() {
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
    videoPreview.srcObject = stream;
  } catch (err) {
    alert('Error accessing camera: ' + err.message);
    disableControls();
  }
}

function disableControls() {
  btnRecord.disabled = true;
  btnPause.disabled = true;
  btnStop.disabled = true;
  btnPlay.disabled = true;
  btnDownload.disabled = true;
}

function enableControls() {
  btnRecord.disabled = false;
  btnPause.disabled = true;
  btnStop.disabled = true;
  btnPlay.disabled = true;
  btnDownload.disabled = true;
}

function updateButtonsOnStart() {
  btnRecord.disabled = true;
  btnPause.disabled = false;
  btnStop.disabled = false;
  btnPlay.disabled = true;
  btnDownload.disabled = true;
  btnPause.textContent = 'Pause';
  btnPause.querySelector('i').className = 'fas fa-pause';
}

function updateButtonsOnStop() {
  btnRecord.disabled = false;
  btnPause.disabled = true;
  btnStop.disabled = true;
  btnPlay.disabled = false;
  btnDownload.disabled = false;
}

function addRecordingToHistory(blob, timestamp) {
  const url = URL.createObjectURL(blob);
  recordings.push({ url, timestamp });

  const li = document.createElement('li');
  li.textContent = `Recording - ${timestamp.toLocaleString()}`;
  li.tabIndex = 0;
  li.classList.add('cursor-pointer');
  li.addEventListener('click', () => {
    videoPreview.srcObject = null;
    videoPreview.src = url;
    videoPreview.controls = true;
    videoPreview.play();
    btnPlay.disabled = false;
    btnDownload.disabled = false;
  });
  recordingHistory.appendChild(li);
}

btnRecord.addEventListener('click', () => {
  if (!stream) {
    alert('Camera not initialized');
    return;
  }
  recordedChunks = [];
  mediaRecorder = new MediaRecorder(stream, { mimeType: 'video/webm' });

  mediaRecorder.ondataavailable = (event) => {
    if (event.data.size > 0) {
      recordedChunks.push(event.data);
    }
  };

  mediaRecorder.onstop = () => {
    const blob = new Blob(recordedChunks, { type: 'video/webm' });
    const timestamp = new Date();
    addRecordingToHistory(blob, timestamp);
    videoPreview.srcObject = null;
    videoPreview.src = URL.createObjectURL(blob);
    videoPreview.controls = true;
    videoPreview.play();
    updateButtonsOnStop();
  };

  mediaRecorder.start();
  isRecording = true;
  isPaused = false;
  updateButtonsOnStart();
});

btnPause.addEventListener('click', () => {
  if (!mediaRecorder) return;
  if (!isPaused) {
    mediaRecorder.pause();
    btnPause.textContent = 'Resume';
    btnPause.querySelector('i').className = 'fas fa-play';
    isPaused = true;
  } else {
    mediaRecorder.resume();
    btnPause.textContent = 'Pause';
    btnPause.querySelector('i').className = 'fas fa-pause';
    isPaused = false;
  }
});

btnStop.addEventListener('click', () => {
  if (!mediaRecorder) return;
  mediaRecorder.stop();
  isRecording = false;
  isPaused = false;
});

btnPlay.addEventListener('click', () => {
  if (videoPreview.srcObject) return;
  videoPreview.play();
});

btnDownload.addEventListener('click', () => {
  if (recordedChunks.length === 0) return;
  const blob = new Blob(recordedChunks, { type: 'video/webm' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.style.display = 'none';
  a.href = url;
  a.download = `recording_${new Date().toISOString()}.webm`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
});

window.addEventListener('load', () => {
  initCamera();
  enableControls();
});
