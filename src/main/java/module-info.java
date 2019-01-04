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
module ru.releng.nwgss {

    requires java.logging;
    requires java.security.sasl;
    requires com.sun.jna;
    requires com.sun.jna.platform;

    provides java.security.Provider with ru.releng.nwgss.SspiKrb5SaslProvider;

}