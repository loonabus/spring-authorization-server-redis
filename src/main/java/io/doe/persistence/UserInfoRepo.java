package io.doe.persistence;

import io.doe.domain.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see UserInfoRepo
 * @since 2024-07-08
 */

@Repository
public interface UserInfoRepo extends JpaRepository<UserInfo, String> { /* no additional operation for now */  }
