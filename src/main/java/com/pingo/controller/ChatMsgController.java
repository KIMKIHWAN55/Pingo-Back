package com.pingo.controller;

import com.pingo.dto.ResponseDTO;
import com.pingo.dto.chat.ChatMsgDTO;
import com.pingo.service.ImageService;
import com.pingo.service.chatService.ChatMsgService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@RestController // @Controller 대신 @RestController 사용 추천
public class ChatMsgController {

    private final ChatMsgService chatMsgService;
    private final ImageService imageService;

    // 해당 채팅방의 메세지 최신 100개 조회
    @GetMapping("/select/message")
    public ResponseEntity<?> selectMessage(@RequestParam String roomId){
        log.info("조회할 roomId: " + roomId);
        List<ChatMsgDTO> chatMsgDTOS = chatMsgService.selectMessage(roomId);
        return ResponseEntity.ok().body(ResponseDTO.of("1", "성공", chatMsgDTOS));
    }

    // 스크롤 시 과거 채팅 메세지 조회
    @GetMapping("/select/oldMessage")
    public ResponseEntity<?> selectOldMessage(@RequestParam String msgId, @RequestParam String roomId) {
        log.info("과거 메세지 조회 - roomId: {}, 기준 msgId: {}", roomId, msgId);
        List<ChatMsgDTO> chatMsgDTOS = chatMsgService.selectOldMessage(msgId, roomId);
        return ResponseEntity.ok().body(ResponseDTO.of("1", "성공", chatMsgDTOS));
    }

    // 받은 메세지에서 이미지/파일 서버에 저장하기
    @PostMapping("/chat/save/chatFile")
    public ResponseEntity<?> saveImage(@RequestPart("roomId") String roomId,
                                       @RequestPart("chatFile") MultipartFile chatFile) {
        log.info("파일 업로드 요청 - roomId: {}", roomId);
        log.info("업로드 파일명: {}", chatFile.getOriginalFilename());

        // 고유 파일명 생성
        String chatFileName = "CI_" + UUID.randomUUID().toString();

        // 폴더명을 "chatFiles"로 고정하여 넘겨줌 (무한 폴더 생성 방지)
        String fileUrl = imageService.imageUpload(chatFile, "chatFiles", chatFileName);

        log.info("저장된 이미지 경로: " + fileUrl);
        return ResponseEntity.ok().body(ResponseDTO.of("1", "성공", fileUrl));
    }
}