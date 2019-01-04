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

import java.util.Objects;

public final class SecurityContextRequirements {

    private final boolean confidentiality;
    private final boolean integrity;
    private final boolean mutualAuthentication;
    private final boolean replayDetect;
    private final boolean sequenceDetect;
    private final boolean delegation;

    private SecurityContextRequirements(boolean confidentiality, boolean integrity, boolean mutualAuthentication,
                                       boolean replayDetect, boolean sequenceDetect, boolean delegation)
    {
        this.confidentiality = confidentiality;
        this.integrity = integrity;
        this.mutualAuthentication = mutualAuthentication;
        this.replayDetect = replayDetect;
        this.sequenceDetect = sequenceDetect;
        this.delegation = delegation;
    }

    public static Builder builder() {
        return new Builder();
    }

    public boolean isConfidentiality() {
        return confidentiality;
    }

    public boolean isIntegrity() {
        return integrity;
    }

    public boolean isMutualAuthentication() {
        return mutualAuthentication;
    }

    public boolean isReplayDetect() {
        return replayDetect;
    }

    public boolean isSequenceDetect() {
        return sequenceDetect;
    }

    public boolean isDelegation() {
        return delegation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityContextRequirements that = (SecurityContextRequirements) o;
        return confidentiality == that.confidentiality
                && integrity == that.integrity
                && mutualAuthentication == that.mutualAuthentication
                && replayDetect == that.replayDetect
                && sequenceDetect == that.sequenceDetect
                && delegation == that.delegation;
    }

    @Override
    public int hashCode() {
        return Objects.hash(confidentiality, integrity, mutualAuthentication, replayDetect, sequenceDetect, delegation);
    }

    @Override
    public String toString() {
        return "SecurityContextRequirements{"
                + "confidentiality=" + confidentiality
                + ", integrity=" + integrity
                + ", mutualAuthentication=" + mutualAuthentication
                + ", replayDetect=" + replayDetect
                + ", sequenceDetect=" + sequenceDetect
                + ", delegation=" + delegation
                + '}';
    }

    public static final class Builder {

        private boolean confidentiality;
        private boolean integrity;
        private boolean mutualAuthentication;
        private boolean replayDetect;
        private boolean sequenceDetect;
        private boolean delegation;

        private Builder() {
        }

        public Builder setConfidentiality(boolean confidentiality) {
            this.confidentiality = confidentiality;
            return this;
        }

        public Builder setIntegrity(boolean integrity) {
            this.integrity = integrity;
            return this;
        }

        public Builder setMutualAuthentication(boolean mutualAuthentication) {
            this.mutualAuthentication = mutualAuthentication;
            return this;
        }

        public Builder setReplayDetect(boolean replayDetect) {
            this.replayDetect = replayDetect;
            return this;
        }

        public Builder setSequenceDetect(boolean sequenceDetect) {
            this.sequenceDetect = sequenceDetect;
            return this;
        }

        public Builder setDelegation(boolean delegation) {
            this.delegation = delegation;
            return this;
        }

        public SecurityContextRequirements build() {
            return new SecurityContextRequirements(confidentiality, integrity, mutualAuthentication, replayDetect,
                    sequenceDetect, delegation);
        }

    }

}
