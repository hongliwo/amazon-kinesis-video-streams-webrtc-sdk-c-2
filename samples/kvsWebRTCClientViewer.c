#include "Samples.h"

extern PSampleConfiguration gSampleConfiguration;

#ifdef ENABLE_DATA_CHANNEL

// onMessage callback for a message received by the viewer on a data channel
VOID dataChannelOnMessageCallback(UINT64 customData, PRtcDataChannel pDataChannel, BOOL isBinary, PBYTE pMessage, UINT32 pMessageLen)
{
    UNUSED_PARAM(customData);
    UNUSED_PARAM(pDataChannel);
    if (isBinary) {
        DLOGI("DataChannel Binary Message");
    } else {
        DLOGI("DataChannel String Message: %.*s", pMessageLen, pMessage);
    }
}

// onOpen callback for the onOpen event of a viewer created data channel
VOID dataChannelOnOpenCallback(UINT64 customData, PRtcDataChannel pDataChannel)
{
    STATUS retStatus = STATUS_SUCCESS;
    DLOGI("New DataChannel has been opened %s ", pDataChannel->name);
    dataChannelOnMessage(pDataChannel, customData, dataChannelOnMessageCallback);
    ATOMIC_INCREMENT((PSIZE_T) customData);
    // Sending first message to the master over the data channel
    retStatus = dataChannelSend(pDataChannel, FALSE, (PBYTE) VIEWER_DATA_CHANNEL_MESSAGE, STRLEN(VIEWER_DATA_CHANNEL_MESSAGE));
    if (retStatus != STATUS_SUCCESS) {
        DLOGI("[KVS Viewer] dataChannelSend(): operation returned status code: 0x%08x ", retStatus);
    }
}
#endif

STATUS readFrameFromDisk(PBYTE pFrame, PUINT32 pSize, PCHAR frameFilePath)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 size = 0;
    CHK_ERR(pSize != NULL, STATUS_NULL_ARG, "[KVS Master] Invalid file size");
    size = *pSize;
    // Get the size and read into frame
    CHK_STATUS(readFile(frameFilePath, TRUE, pFrame, &size));
CleanUp:

    if (pSize != NULL) {
        *pSize = (UINT32) size;
    }

    return retStatus;
}

PVOID sendVideoPackets(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    RtcEncoderStats encoderStats;
    Frame frame;
    UINT32 fileIndex = 1, frameSize;
    CHAR filePath[MAX_PATH_LEN + 1];
    STATUS status = STATUS_SRTP_NOT_READY_YET;
    UINT32 i;
    UINT64 startTime, lastFrameTime, elapsed;
    MEMSET(&encoderStats, 0x00, SIZEOF(RtcEncoderStats));
    CHK_ERR(pSampleConfiguration != NULL, STATUS_NULL_ARG, "[KVS Master] Streaming session is NULL");

    frame.presentationTs = 0;
    startTime = GETTIME();
    lastFrameTime = startTime;
    DLOGI("Sending video packets");
    while (!ATOMIC_LOAD_BOOL(&pSampleConfiguration->appTerminateFlag)) {
        if (status == STATUS_SUCCESS) {
            fileIndex = fileIndex % NUMBER_OF_H264_FRAME_FILES + 1;
        }
        SNPRINTF(filePath, MAX_PATH_LEN, "./h264SampleFrames/frame-%04d.h264", fileIndex);
        CHK_STATUS(readFrameFromDisk(NULL, &frameSize, filePath));

        // Re-alloc if needed
        if (frameSize > pSampleConfiguration->videoBufferSize) {
            pSampleConfiguration->pVideoFrameBuffer = (PBYTE) MEMREALLOC(pSampleConfiguration->pVideoFrameBuffer, frameSize);
            CHK_ERR(pSampleConfiguration->pVideoFrameBuffer != NULL, STATUS_NOT_ENOUGH_MEMORY, "[KVS Master] Failed to allocate video frame buffer");
            pSampleConfiguration->videoBufferSize = frameSize;
        }

        frame.frameData = pSampleConfiguration->pVideoFrameBuffer;
        frame.size = frameSize;

        CHK_STATUS(readFrameFromDisk(frame.frameData, &frameSize, filePath));

        // based on bitrate of samples/h264SampleFrames/frame-*
        encoderStats.width = 640;
        encoderStats.height = 480;
        encoderStats.targetBitrate = 262000;
        frame.presentationTs += SAMPLE_VIDEO_FRAME_DURATION;
        MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);
        for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
            status = writeFrame(pSampleConfiguration->sampleStreamingSessionList[i]->pVideoRtcRtpTransceiver, &frame);
            if (pSampleConfiguration->sampleStreamingSessionList[i]->firstFrame && status == STATUS_SUCCESS) {
                PROFILE_WITH_START_TIME(pSampleConfiguration->sampleStreamingSessionList[i]->offerReceiveTime, "Time to first frame");
                pSampleConfiguration->sampleStreamingSessionList[i]->firstFrame = FALSE;
            }
            encoderStats.encodeTimeMsec = 4; // update encode time to an arbitrary number to demonstrate stats update
            updateEncoderStats(pSampleConfiguration->sampleStreamingSessionList[i]->pVideoRtcRtpTransceiver, &encoderStats);
            if (status != STATUS_SRTP_NOT_READY_YET) {
                if (status != STATUS_SUCCESS) {
                    DLOGV("writeFrame() failed with 0x%08x", status);
                }
            }
        }
        MUTEX_UNLOCK(pSampleConfiguration->streamingSessionListReadLock);

        // Adjust sleep in the case the sleep itself and writeFrame take longer than expected. Since sleep makes sure that the thread
        // will be paused at least until the given amount, we can assume that there's no too early frame scenario.
        // Also, it's very unlikely to have a delay greater than SAMPLE_VIDEO_FRAME_DURATION, so the logic assumes that this is always
        // true for simplicity.
        elapsed = lastFrameTime - startTime;
        THREAD_SLEEP(SAMPLE_VIDEO_FRAME_DURATION - elapsed % SAMPLE_VIDEO_FRAME_DURATION);
        lastFrameTime = GETTIME();
    }

CleanUp:
    DLOGI("[KVS Master] Closing video thread");
    CHK_LOG_ERR(retStatus);

    return (PVOID) (ULONG_PTR) retStatus;
}

PVOID sendAudioPackets(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    Frame frame;
    UINT32 fileIndex = 0, frameSize;
    CHAR filePath[MAX_PATH_LEN + 1];
    UINT32 i;
    STATUS status = STATUS_SRTP_NOT_READY_YET;

    CHK_ERR(pSampleConfiguration != NULL, STATUS_NULL_ARG, "[KVS Master] Streaming session is NULL");
    frame.presentationTs = 0;
    DLOGI("Sending audio packets");
    while (!ATOMIC_LOAD_BOOL(&pSampleConfiguration->appTerminateFlag)) {
        if (status == STATUS_SUCCESS) {
            fileIndex = fileIndex % NUMBER_OF_OPUS_FRAME_FILES + 1;
        }
        SNPRINTF(filePath, MAX_PATH_LEN, "./opusSampleFrames/sample-%03d.opus", fileIndex);

        CHK_STATUS(readFrameFromDisk(NULL, &frameSize, filePath));

        // Re-alloc if needed
        if (frameSize > pSampleConfiguration->audioBufferSize) {
            pSampleConfiguration->pAudioFrameBuffer = (UINT8*) MEMREALLOC(pSampleConfiguration->pAudioFrameBuffer, frameSize);
            CHK_ERR(pSampleConfiguration->pAudioFrameBuffer != NULL, STATUS_NOT_ENOUGH_MEMORY, "[KVS Master] Failed to allocate audio frame buffer");
            pSampleConfiguration->audioBufferSize = frameSize;
        }

        frame.frameData = pSampleConfiguration->pAudioFrameBuffer;
        frame.size = frameSize;

        CHK_STATUS(readFrameFromDisk(frame.frameData, &frameSize, filePath));

        frame.presentationTs += SAMPLE_AUDIO_FRAME_DURATION;

        MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);
        for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
            status = writeFrame(pSampleConfiguration->sampleStreamingSessionList[i]->pAudioRtcRtpTransceiver, &frame);
            if (status != STATUS_SRTP_NOT_READY_YET) {
                if (status != STATUS_SUCCESS) {
                    DLOGV("writeFrame() failed with 0x%08x", status);
                } else if (pSampleConfiguration->sampleStreamingSessionList[i]->firstFrame && status == STATUS_SUCCESS) {
                    PROFILE_WITH_START_TIME(pSampleConfiguration->sampleStreamingSessionList[i]->offerReceiveTime, "Time to first frame");
                    pSampleConfiguration->sampleStreamingSessionList[i]->firstFrame = FALSE;
                }
            }
        }
        MUTEX_UNLOCK(pSampleConfiguration->streamingSessionListReadLock);
        THREAD_SLEEP(SAMPLE_AUDIO_FRAME_DURATION);
    }

CleanUp:
    DLOGI("[KVS Master] closing audio thread");
    return (PVOID) (ULONG_PTR) retStatus;
}

INT32 main(INT32 argc, CHAR* argv[])
{
    STATUS retStatus = STATUS_SUCCESS;
    RtcSessionDescriptionInit offerSessionDescriptionInit;
    UINT32 buffLen = 0;
    SignalingMessage message;
    PSampleConfiguration pSampleConfiguration = NULL;
    PSampleStreamingSession pSampleStreamingSession = NULL;
    BOOL locked = FALSE;
    PCHAR pChannelName;
    CHAR clientId[256];

    SET_INSTRUMENTED_ALLOCATORS();
    UINT32 logLevel = setLogLevel();

#ifndef _WIN32
    signal(SIGINT, sigintHandler);
#endif

#ifdef IOT_CORE_ENABLE_CREDENTIALS
    CHK_ERR((pChannelName = getenv(IOT_CORE_THING_NAME)) != NULL, STATUS_INVALID_OPERATION, "AWS_IOT_CORE_THING_NAME must be set");
#else
    pChannelName = argc > 1 ? argv[1] : SAMPLE_CHANNEL_NAME;
#endif

    CHK_STATUS(createSampleConfiguration(pChannelName, SIGNALING_CHANNEL_ROLE_TYPE_VIEWER, TRUE, TRUE, logLevel, &pSampleConfiguration));

    pSampleConfiguration->audioSource = sendAudioPackets;
    pSampleConfiguration->videoSource = sendVideoPackets;

    // Initialize KVS WebRTC. This must be done before anything else, and must only be done once.
    CHK_STATUS(initKvsWebRtc());
    DLOGI("[KVS Viewer] KVS WebRTC initialization completed successfully");

    SPRINTF(clientId, "%s_%u", SAMPLE_VIEWER_CLIENT_ID, RAND() % MAX_UINT32);
    CHK_STATUS(initSignaling(pSampleConfiguration, clientId));
    DLOGI("[KVS Viewer] Signaling client connection established");

    // Initialize streaming session
    MUTEX_LOCK(pSampleConfiguration->sampleConfigurationObjLock);
    locked = TRUE;
    CHK_STATUS(createSampleStreamingSession(pSampleConfiguration, NULL, FALSE, &pSampleStreamingSession));
    DLOGI("[KVS Viewer] Creating streaming session...completed");
    pSampleConfiguration->sampleStreamingSessionList[pSampleConfiguration->streamingSessionCount++] = pSampleStreamingSession;

    MUTEX_UNLOCK(pSampleConfiguration->sampleConfigurationObjLock);
    locked = FALSE;

    MEMSET(&offerSessionDescriptionInit, 0x00, SIZEOF(RtcSessionDescriptionInit));

    offerSessionDescriptionInit.useTrickleIce = pSampleStreamingSession->remoteCanTrickleIce;
    CHK_STATUS(setLocalDescription(pSampleStreamingSession->pPeerConnection, &offerSessionDescriptionInit));
    DLOGI("[KVS Viewer] Completed setting local description");

    CHK_STATUS(transceiverOnFrame(pSampleStreamingSession->pAudioRtcRtpTransceiver, (UINT64) pSampleStreamingSession, sampleAudioFrameHandler));

    if (!pSampleConfiguration->trickleIce) {
        DLOGI("[KVS Viewer] Non trickle ice. Wait for Candidate collection to complete");
        MUTEX_LOCK(pSampleConfiguration->sampleConfigurationObjLock);
        locked = TRUE;

        while (!ATOMIC_LOAD_BOOL(&pSampleStreamingSession->candidateGatheringDone)) {
            CHK_WARN(!ATOMIC_LOAD_BOOL(&pSampleStreamingSession->terminateFlag), STATUS_OPERATION_TIMED_OUT,
                     "application terminated and candidate gathering still not done");
            CVAR_WAIT(pSampleConfiguration->cvar, pSampleConfiguration->sampleConfigurationObjLock, 5 * HUNDREDS_OF_NANOS_IN_A_SECOND);
        }

        MUTEX_UNLOCK(pSampleConfiguration->sampleConfigurationObjLock);
        locked = FALSE;

        DLOGI("[KVS Viewer] Candidate collection completed");
    }

    CHK_STATUS(createOffer(pSampleStreamingSession->pPeerConnection, &offerSessionDescriptionInit));
    DLOGI("[KVS Viewer] Offer creation successful");

    DLOGI("[KVS Viewer] Generating JSON of session description....");
    CHK_STATUS(serializeSessionDescriptionInit(&offerSessionDescriptionInit, NULL, &buffLen));

    if (buffLen >= SIZEOF(message.payload)) {
        DLOGE("[KVS Viewer] serializeSessionDescriptionInit(): operation returned status code: 0x%08x ", STATUS_INVALID_OPERATION);
        retStatus = STATUS_INVALID_OPERATION;
        goto CleanUp;
    }

    CHK_STATUS(serializeSessionDescriptionInit(&offerSessionDescriptionInit, message.payload, &buffLen));

    message.version = SIGNALING_MESSAGE_CURRENT_VERSION;
    message.messageType = SIGNALING_MESSAGE_TYPE_OFFER;
    STRCPY(message.peerClientId, SAMPLE_MASTER_CLIENT_ID);
    message.payloadLen = (buffLen / SIZEOF(CHAR)) - 1;
    message.correlationId[0] = '\0';

    CHK_STATUS(signalingClientSendMessageSync(pSampleConfiguration->signalingClientHandle, &message));
#ifdef ENABLE_DATA_CHANNEL
    PRtcDataChannel pDataChannel = NULL;
    PRtcPeerConnection pPeerConnection = pSampleStreamingSession->pPeerConnection;
    SIZE_T datachannelLocalOpenCount = 0;

    // Creating a new datachannel on the peer connection of the existing sample streaming session
    CHK_STATUS(createDataChannel(pPeerConnection, pChannelName, NULL, &pDataChannel));
    DLOGI("[KVS Viewer] Creating data channel...completed");

    // Setting a callback for when the data channel is open
    CHK_STATUS(dataChannelOnOpen(pDataChannel, (UINT64) &datachannelLocalOpenCount, dataChannelOnOpenCallback));
    DLOGI("[KVS Viewer] Data Channel open now...");
#endif

    // Block until interrupted
    while (!ATOMIC_LOAD_BOOL(&pSampleConfiguration->interrupted) && !ATOMIC_LOAD_BOOL(&pSampleStreamingSession->terminateFlag)) {
        THREAD_SLEEP(HUNDREDS_OF_NANOS_IN_A_SECOND);
    }

CleanUp:

    if (retStatus != STATUS_SUCCESS) {
        DLOGE("[KVS Viewer] Terminated with status code 0x%08x", retStatus);
    }

    DLOGI("[KVS Viewer] Cleaning up....");

    if (locked) {
        MUTEX_UNLOCK(pSampleConfiguration->sampleConfigurationObjLock);
    }

    if (pSampleConfiguration->mediaSenderTid != INVALID_TID_VALUE) {
        THREAD_JOIN(pSampleConfiguration->mediaSenderTid, NULL);
    }

    if (pSampleConfiguration->enableFileLogging) {
        freeFileLogger();
    }
    if (pSampleConfiguration != NULL) {
        retStatus = freeSignalingClient(&pSampleConfiguration->signalingClientHandle);
        if (retStatus != STATUS_SUCCESS) {
            DLOGE("[KVS Viewer] freeSignalingClient(): operation returned status code: 0x%08x ", retStatus);
        }

        retStatus = freeSampleConfiguration(&pSampleConfiguration);
        if (retStatus != STATUS_SUCCESS) {
            DLOGE("[KVS Viewer] freeSampleConfiguration(): operation returned status code: 0x%08x ", retStatus);
        }
    }
    DLOGI("[KVS Viewer] Cleanup done");

    RESET_INSTRUMENTED_ALLOCATORS();

    // https://www.gnu.org/software/libc/manual/html_node/Exit-Status.html
    // We can only return with 0 - 127. Some platforms treat exit code >= 128
    // to be a success code, which might give an unintended behaviour.
    // Some platforms also treat 1 or 0 differently, so it's better to use
    // EXIT_FAILURE and EXIT_SUCCESS macros for portability.
    return STATUS_FAILED(retStatus) ? EXIT_FAILURE : EXIT_SUCCESS;
}
