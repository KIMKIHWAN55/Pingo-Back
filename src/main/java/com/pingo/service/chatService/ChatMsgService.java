package com.pingo.service.chatService;

import com.pingo.document.ChatMsgDocument;
import com.pingo.dto.chat.ChatMsgDTO;
import com.pingo.repository.ChatMsgRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class ChatMsgService {
    private final ChatMsgRepository chatMsgRepository;

    // 최신 메세지 조회
    public List<ChatMsgDTO> selectMessage(String roomId){
        Pageable pageable = PageRequest.of(0, 100); // 여기서 생성
        return chatMsgRepository.findByRoomId(roomId, pageable);
    }

    // 과거 메세지 무한스크롤 조회
    public List<ChatMsgDTO> selectOldMessage(String msgId, String roomId){
        Pageable pageable = PageRequest.of(0, 100); // 여기서 생성
        return chatMsgRepository.findByMsgId(roomId, msgId, pageable);
    }


    // 메세지 삽입
    public ChatMsgDTO insertMessage(ChatMsgDTO chatMsgDTO){
        ChatMsgDocument chatMsgDsgDocument = ChatMsgDocument.builder()
                .roomId(chatMsgDTO.getRoomId())
                .msgContent(chatMsgDTO.getMsgContent())
                .fileName(chatMsgDTO.getFileName())
                .msgTime(chatMsgDTO.getMsgTime())
                .isRead(chatMsgDTO.isRead())
                .userNo(chatMsgDTO.getUserNo())
                .msgType(chatMsgDTO.getMsgType())
                .build();
        ChatMsgDocument savedDocument = chatMsgRepository.save(chatMsgDsgDocument);
        log.info("챗저장 값 : " +savedDocument);
        chatMsgDTO.setMsgId(savedDocument.getMsgId());
        return chatMsgDTO;

    }

}
