/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package cache

import (
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/boltdb/bolt"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// DB has a cache instance
var DB Cache

const metabucket = "changelog-meta"

// Cache is a interface of cache
type Cache interface {
	Close() error
	GetMeta(string) (Meta, bool, error)
	EnsureBuckets(Meta) error
	PrettyPrint(Meta) error
}

// Bolt holds a pointer of bolt.DB
// boltdb is used to store a cache of Changelogs of Ubuntu/Debian
type Bolt struct {
	Path string
	Log  *logrus.Entry
	db   *bolt.DB
}

// Meta holds a server name, distro information of the scanned server and
// package information that was collected at the last scan.
type Meta struct {
	Name   string
	Distro config.Distro
	Packs  []models.PackageInfo
}

// FindPack search a PackageInfo
func (m Meta) FindPack(name string) (pack models.PackageInfo, found bool) {
	for _, p := range m.Packs {
		if name == p.Name {
			return p, true
		}
	}
	return pack, false
}

// SetupBolt opens a boltdb and creates a meta bucket if not exists.
func SetupBolt(path string, l *logrus.Entry) error {
	l.Infof("Open boltDB: %s", path)
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return err
	}

	b := Bolt{
		Path: path,
		Log:  l,
		db:   db}
	if err = b.createBucketIfNotExists(metabucket); err != nil {
		return err
	}

	DB = b
	return nil
}

// Close a db.
func (b Bolt) Close() error {
	return b.db.Close()
}

//  CreateBucketIfNotExists creates a buket that is specified by arg.
func (b *Bolt) createBucketIfNotExists(name string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(name))
		if err != nil {
			return fmt.Errorf("Failed to create bucket: %s", err)
		}
		return nil
	})
}

// GetMeta gets a Meta Information os the servername to boltdb.
func (b Bolt) GetMeta(serverName string) (meta Meta, found bool, err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(metabucket))
		v := bkt.Get([]byte(serverName))
		if len(v) == 0 {
			found = false
			return nil
		}
		if e := json.Unmarshal(v, &meta); e != nil {
			return e
		}
		found = true
		return nil
	})
	return
}

// EnsureBuckets puts a Meta information and create a buket that holds changelogs.
func (b Bolt) EnsureBuckets(meta Meta) error {
	jsonBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("Failed to Marshal to JSON: %s", err)
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		b.Log.Debugf("Put to meta: %s", meta.Name)
		bkt := tx.Bucket([]byte(metabucket))
		if err := bkt.Put([]byte(meta.Name), jsonBytes); err != nil {
			return err
		}

		// re-create a bucket (bucket name: servername)
		bkt = tx.Bucket([]byte(meta.Name))
		if bkt != nil {
			b.Log.Debugf("Delete Bucket: %s", meta.Name)
			if err := bkt.DeleteBucket([]byte(meta.Name)); err != nil {
				return err
			}
		}
		b.Log.Debugf("Create Bucket: %s", meta.Name)
		if _, err := tx.CreateBucket([]byte(meta.Name)); err != nil {
			return err
		}
		return nil
	})
}

// PrettyPrint is for debuging
func (b Bolt) PrettyPrint(meta Meta) error {
	return b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(metabucket))
		v := bkt.Get([]byte(meta.Name))
		b.Log.Debugf("key=%s, value=%s\n", meta.Name, v)

		bkt = tx.Bucket([]byte(meta.Name))
		c := bkt.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			b.Log.Debugf("key=%s, value=%s\n", k, v[:100])
		}
		return nil
	})
}
