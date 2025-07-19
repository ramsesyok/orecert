/*
Copyright © 2025 ramsesyok

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "orecert",
	Short: "自己署名証明書管理ツール",
	Long: `orecert はローカル開発向けに自己署名証明書を生成・管理する CLI ツールです。
YAML で定義したプロファイルをもとに鍵や証明書を作成し、検証・失効・梱包などを行えます。`,
}

// Execute は rootCmd を実行します。
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	cobra.MousetrapHelpText = ""

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.orecert.yaml)")

}

// initConfig は設定ファイルと環境変数を読み込みます。
func initConfig() {
	if cfgFile != "" {
		// フラグで指定された設定ファイルを使用します。
		viper.SetConfigFile(cfgFile)
	} else {
		// 実行ファイルのディレクトリを取得します。
		exe, err := os.Executable()
		cobra.CheckErr(err)
		exeDir := filepath.Dir(exe)

		// 実行ファイルのディレクトリで .orecert 設定を探します。
		viper.AddConfigPath(exeDir)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".orecert")
	}

	viper.AutomaticEnv() // 環境変数も読み込みます。

	// 設定ファイルが見つかった場合は読み込みます。
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
