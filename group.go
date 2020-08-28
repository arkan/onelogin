package onelogin

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"golang.org/x/net/context"
)

// GroupService deals with OneLogin groups.
type GroupService service

type Group struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Reference string `json:"reference"`
}

type GroupResponse struct {
	Status struct {
		Error   bool   `json:"error"`
		Code    int    `json:"code"`
		Type    string `json:"type"`
		Message string `json:"message`
	} `json:"status"`
	Pagination struct {
		Before   string `json:"before_cursor"`
		After    string `json:"after_curson"`
		Previous string `json:"previous_link"`
		Next     string `json:"next_link"`
	} `json:"pagination"`
	Data []Group `json:"data"`
}

// GetGroups returns all the OneLogin groups.
func (s *GroupService) GetGroups(ctx context.Context) ([]Group, error) {
	u := "/api/1/groups"

	groups := []Group{}
	var afterCursor string = ""

	for {
		uu, err := addOptions(u, &urlQuery{AfterCursor: afterCursor})
		if err != nil {
			return nil, err
		}

		req, err := s.client.NewRequest("GET", uu, nil)
		if err != nil {
			return nil, err
		}

		if err := s.client.AddAuthorization(ctx, req); err != nil {
			return nil, err
		}

		resp, err := s.client.DoGroups(ctx, req)
		if err != nil {
			return nil, err
		}

		groups = append(groups, resp.Data...)

		if resp.Pagination.After != "" {
			afterCursor = resp.Pagination.After
		} else {
			break
		}
	}

	return groups, nil
}

func (c *Client) DoGroups(ctx context.Context, req *http.Request) (*GroupResponse, error) {
	req = req.WithContext(ctx)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var groupResp *GroupResponse = nil
	err = json.Unmarshal(body, groupResp)
	if err != nil {
		return nil, err
	}

	if groupResp == nil {
		return nil, errors.New("empy group response from onelogin")
	}

	if groupResp.Status.Error {
		return groupResp, errors.New("group response from onelogin returned error")
	}

	return groupResp, nil
}
