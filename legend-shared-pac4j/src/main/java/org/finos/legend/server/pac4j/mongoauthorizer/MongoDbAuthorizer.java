// Copyright 2020 Goldman Sachs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.finos.legend.server.pac4j.mongoauthorizer;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import java.util.List;
import org.bson.Document;
import org.finos.legend.server.pac4j.MongoDbConsumer;
import org.pac4j.core.authorization.authorizer.AbstractCheckAuthenticationAuthorizer;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.CommonProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.pac4j.core.profile.UserProfile;

@SuppressWarnings("unused")
public class MongoDbAuthorizer extends AbstractCheckAuthenticationAuthorizer<UserProfile>
    implements MongoDbConsumer {
  public static final String NAME = "mongoAuthorizer";
  private static final Logger logger = LoggerFactory.getLogger(MongoDbAuthorizer.class);
  private MongoCollection<Document> collection;

  @JsonProperty
  private String collectionName;

  @Override
  public boolean isProfileAuthorized(WebContext webContext, UserProfile u) {
    if (!(u instanceof CommonProfile)) {
      return false;
    }
    String id = ((CommonProfile) u).getId();
    Document doc = collection.find(new Document("_id", id)).first();
    if (doc != null) {
      logger.debug("Allowing user {} - found in Mongo Collection", id);
      return true;
    } else {
      logger.warn("Disallowing user {} - not found in Mongo Collection", id);
      return false;
    }
  }

  @Override
  public boolean isAuthorized(WebContext context, List<UserProfile> profiles) {
    return profiles.stream().anyMatch(p -> isProfileAuthorized(context, p));
  }

  @Override
  public void setupDb(MongoDatabase database) {
    if (collectionName == null) {
      throw new RuntimeException("Collection name must be specified");
    }
    collection = database.getCollection(collectionName);
  }
}
