import React, { useState } from "react";
import { ActivityIndicator, Text } from "react-native";
import { ThemedView } from "@/components/ThemedView";
import { useAuth } from "@/context/auth";
import LoginForm from "@/components/LoginForm";
import SignupForm from "@/components/SignupForm";
import ProfileCard from "@/components/ProfileCard";
import ProtectedRequestCard from "@/components/ProtectedRequestCard";

export default function HomeScreen() {
  const { user, isLoading } = useAuth();
  const [showSignup, setShowSignup] = useState(false);

  if (isLoading) {
    return (
      <ThemedView
        style={{ flex: 1, justifyContent: "center", alignItems: "center" }}
      >
        <ActivityIndicator />
      </ThemedView>
    );
  }

  if (!user) {
    return (
      <ThemedView
        style={{ flex: 1, justifyContent: "center", alignItems: "center" }}
      >
        {showSignup ? <SignupForm /> : <LoginForm />}
        <Text
          style={{ marginTop: 20, color: "#007AFF", textDecorationLine: "underline" }}
          onPress={() => setShowSignup((s) => !s)}
        >
          {showSignup ? "Already have an account? Log in" : "Don't have an account? Sign up"}
        </Text>
      </ThemedView>
    );
  }

  return (
    <ThemedView
      style={{
        flex: 1,
        justifyContent: "center",
        alignItems: "center",
        gap: 20,
      }}
    >
      <ProfileCard />
      <ProtectedRequestCard />
    </ThemedView>
  );
}
