// Copyright 2019 rel-eng
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ru.releng.nwgss.sspi;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.win32.W32APITypeMapper;

import java.nio.charset.StandardCharsets;

public interface SspiExt {

    @Structure.FieldOrder({"User", "UserLength", "Domain", "DomainLength", "Password", "PasswordLength", "Flags"})
    class SEC_WINNT_AUTH_IDENTITY extends Structure {
        public String User;
        public int UserLength;
        public String Domain;
        public int DomainLength;
        public Pointer Password;
        public int PasswordLength;
        public int Flags = Sspi.SEC_WINNT_AUTH_IDENTITY_UNICODE;

        public SEC_WINNT_AUTH_IDENTITY() {
            super(W32APITypeMapper.UNICODE);
        }

        @Override
        public void write() {
            this.UserLength = this.User == null ? 0 : this.User.getBytes(StandardCharsets.UTF_16LE).length;
            this.DomainLength = this.Domain == null ? 0 : this.Domain.getBytes(StandardCharsets.UTF_16LE).length;
            super.write();
        }

    }

}
