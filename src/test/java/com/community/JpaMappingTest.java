package com.community;

import com.community.web.domain.Board;
import com.community.web.domain.User;
import com.community.web.domain.enums.BoardType;
import com.community.web.repository.BoardRepository;
import com.community.web.repository.UserRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.time.LocalDateTime;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

@RunWith(SpringRunner.class)
@DataJpaTest
public class JpaMappingTest {
    @Autowired
    UserRepository userRepository;
    @Autowired
    BoardRepository boardRepository;

    private final String testTitle = "게시판 테스트";
    private final String testEmail = "tester@naver.com";

    @Before
    public void init() {
        User user = User.builder().name("김종민").email(testEmail).password("1234").createdDate(LocalDateTime.now()).build();

        userRepository.save(user);

        Board board = Board.builder().title(testTitle).subtitle(testTitle).boardType(BoardType.free).user(user).build();

        boardRepository.save(board);
    }

    @Test
    public void USER와BOARD_DB저장확인() {
        User user = userRepository.findByEmail(testEmail).orElse(null);

        assertThat(user, notNullValue());
        assertThat(user.getEmail(), is(testEmail));

        Board board = boardRepository.findByUser(user).orElse(null);
        assertThat(board, notNullValue());
        assertThat(board.getTitle(), is(testEmail));
    }

}
