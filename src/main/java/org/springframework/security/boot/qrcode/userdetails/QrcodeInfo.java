/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.qrcode.userdetails;

import lombok.Data;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */
@Data
public class QrcodeInfo {
	
	/**
	 * 二维码UUID
	 */
	protected String uuid;
	/**
	 * uuid 对应的用户ID（移动端扫码后才会获取到数据）
	 */
	protected String userId;

}
