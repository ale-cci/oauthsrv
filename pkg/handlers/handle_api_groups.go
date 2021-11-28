package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/mux"
	"go.mongodb.org/mongo-driver/bson"
)

func handleGroups(cnf *Config, w http.ResponseWriter, r *http.Request) {
	handler := CheckJWT(handleGroupsGET, func(_ jwt.JWTBody) error { return nil })
	handler(cnf, w, r)
}

type JSONApi struct {
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

func getJWTBody(r *http.Request) (jwt.JWTBody, error) {
	authHeader := r.Header.Get("authorization")
	var encodedJWT string
	fmt.Sscanf(authHeader, "Bearer %s", &encodedJWT)

	decodedJWT, err := jwt.Decode(encodedJWT)
	if err != nil {
		return nil, fmt.Errorf("Unable to get body from jwt: %v", err)
	}
	jwtBody := decodedJWT.Body
	return jwtBody, nil
}

func canReadGroups(groups []string) []regexp.Regexp {
	regs := []regexp.Regexp{}
	allMatcher := regexp.MustCompile(".*")

	roleMatchers := []*regexp.Regexp{
		regexp.MustCompile("^(.*):admin$"),
		regexp.MustCompile("^(.*):manager$"),
	}

	for _, group := range groups {
		if group == "admin" || group == "manager" {
			return append(regs, *allMatcher)
		}

		for _, roleMatcher := range roleMatchers {
			matches := roleMatcher.FindStringSubmatch(group)

			if len(matches) > 0 {
				groupName := matches[1]
				reg := fmt.Sprintf("%s:.*", groupName)
				regs = append(regs, *regexp.MustCompile(reg))
			}
		}
	}
	return regs
}

func handleGroupsGET(cnf *Config, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	encoder := json.NewEncoder(w)

	jwtBody, _ := getJWTBody(r)
	subId := jwtBody["sub"]

	params := mux.Vars(r)
	requestedId := params["user_id"]

	var readableGroups []regexp.Regexp
	{
		// retrieve sub groups
		var user struct {
			Groups []string `json:"groups"`
		}
		cnf.Database.Collection("identities").FindOne(
			r.Context(),
			bson.D{{Key: "_id", Value: subId}},
		).Decode(&user)

		readableGroups = canReadGroups(user.Groups)
	}

	if subId != requestedId && len(readableGroups) == 0 {
		w.WriteHeader(http.StatusForbidden)
		encoder.Encode(JSONApi{
			Message: "Tokens lacks the permission to read user groups",
		})
		return
	}

	// retrieve sub groups
	var user struct {
		Groups []string `json:"groups"`
	}

	cnf.Database.Collection("identities").FindOne(
		r.Context(),
		bson.D{{Key: "_id", Value: requestedId}},
	).Decode(&user)

	visibleGroups := []string{}

	for _, group := range user.Groups {
		hasMatch := subId == requestedId
		if !hasMatch {
			for _, reg := range readableGroups {
				if reg.MatchString(group) {
					hasMatch = true
				}
			}
		}

		if hasMatch {
			visibleGroups = append(visibleGroups, group)
		}
	}
	user.Groups = visibleGroups

	encoder.Encode(JSONApi{
		Data: user,
	})
}
