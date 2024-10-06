package io.doe.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.SourceType;

import java.time.LocalDateTime;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see User
 * @since 2024-07-30
 */

@Entity @Table(name="USER_INFO")
@Getter @ToString @NoArgsConstructor(access=AccessLevel.PROTECTED)
public class UserInfo {

	@Id private String userId;
	@NotNull private String userPw;
	private String adminYn;
	@CreationTimestamp(source=SourceType.DB) private LocalDateTime createDt;

	@Builder
	public UserInfo(String userId, String userPw, String adminYn, LocalDateTime createDt) {
		this.userId = userId; this.userPw = userPw; this.adminYn = adminYn; this.createDt = createDt;
	}
}
