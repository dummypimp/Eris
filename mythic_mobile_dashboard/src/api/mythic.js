// src/api/mythic.js
import { gql } from "@apollo/client";

export const LIST_MOBILE_DEVICES = gql`
  query ListMobileDevices($campaignID: String!) {
    callbacks(
      where: {
        registered_payload_type: { os: { _eq: "android" } }
        campaign: { _eq: $campaignID }
      }
    ) {
      id
      display_id
      description
      ip
      user
      last_checkin
      pid
      host
      status
      ...
    }
  }
`;
// Usage: ApolloProvider + useQuery(LIST_MOBILE_DEVICES, { variables: { campaignID } });
import { gql } from "@apollo/client";

export const GET_CALLBACKS = gql`
  query GetCallbacks($campaignID: String!) {
    callbacks(where: { campaign: { _eq: $campaignID } }) {
      id
      display_id
      description
      ip
      user
      last_checkin
      pid
      host
      status
      os
      platform
      operator
    }
  }
`;

// More queries and mutations for tasks, artifacts, events, etc., would be added here.
